// SPDX-License-Identifier: Apache-2.0

//! Validation of the serialized document against the model and the syntax.
//!
//! Two layers run here:
//!
//! 1. **Model rules** ([`validate_model`]) — the checks the semantic model makes on
//!    itself. Rule identifiers follow EN 16931 where the check is the same rule
//!    (for example `BR-02` for a missing invoice number); checks that only describe
//!    this crate's shape rules use a `MODEL-` prefix.
//! 2. **Syntax and figure checks** ([`validate_document`]) — the document is parsed
//!    back from its bytes and checked for well-formedness, requirement and element
//!    order, namespaces, datatypes, code lists, and every figure is compared with
//!    the model that produced it. A serializer bug therefore fails validation
//!    instead of producing a plausible-looking but wrong document.
//!
//! ## What this is not
//!
//! The official UBL 2.1 and CII D16B schema files are **not** vendored in this
//! repository, so this module does not execute an XSD validator. It checks the
//! structure the schemas require (element names, order, cardinality, namespaces,
//! datatypes) and the figures, which is enough to make the golden invoices
//! self-consistent; it is not a substitute for validating against the published
//! XSDs with a schema-aware processor in the deployment pipeline. Nothing here
//! claims conformance to a national profile or to a platform's extra rules.

use crate::cii;
use crate::model::{
    format_money, format_percent, format_quantity, Date, DocumentType, Invoice, Party,
    ValidationIssue,
};
use crate::ubl;
use crate::xml::{self, Node};

/// Which syntax binding a document uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Syntax {
    /// UBL 2.1 Invoice / CreditNote.
    Ubl,
    /// UN/CEFACT CII D16B CrossIndustryInvoice.
    Cii,
}

impl Syntax {
    /// Stable identifier used in file names, manifests and the CLI.
    pub fn id(self) -> &'static str {
        match self {
            Syntax::Ubl => "ubl",
            Syntax::Cii => "cii",
        }
    }

    /// Parse the identifier.
    pub fn from_id(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ubl" => Some(Syntax::Ubl),
            "cii" => Some(Syntax::Cii),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn label(self) -> &'static str {
        match self {
            Syntax::Ubl => "UBL 2.1",
            Syntax::Cii => "CII D16B",
        }
    }
}

/// The outcome of validating one document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Syntax that was validated.
    pub syntax: Syntax,
    /// Whether the document is valid; false as soon as one fatal issue is found.
    pub valid: bool,
    /// Findings, in the order they were detected.
    pub issues: Vec<ValidationIssue>,
}

impl Report {
    /// An empty report for `syntax`.
    pub fn new(syntax: Syntax) -> Self {
        Self {
            syntax,
            valid: true,
            issues: Vec::new(),
        }
    }

    /// Record a finding.
    pub fn push(&mut self, issue: ValidationIssue) {
        if issue.fatal {
            self.valid = false;
        }
        self.issues.push(issue);
    }

    /// Number of fatal findings.
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|issue| issue.fatal).count()
    }

    /// Number of non-fatal findings.
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|issue| !issue.fatal).count()
    }

    /// Findings as one line each: `error BR-02 number: ...`.
    pub fn render(&self) -> String {
        self.issues
            .iter()
            .map(|issue| {
                format!(
                    "{} {} {}: {}",
                    if issue.fatal { "error" } else { "warning" },
                    issue.rule,
                    issue.path,
                    issue.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Every model rule finding for `invoice`.
pub fn validate_model(invoice: &Invoice) -> Vec<ValidationIssue> {
    invoice.validate()
}

/// Validate a serialized document against the invoice it must represent.
pub fn validate_document(document: &str, invoice: &Invoice, syntax: Syntax) -> Report {
    let mut report = Report::new(syntax);
    for issue in invoice.validate() {
        report.push(issue);
    }
    let root = match xml::parse(document) {
        Ok(root) => root,
        Err(error) => {
            report.push(ValidationIssue::error(
                "XML-01",
                "document",
                format!("the document is not well-formed XML: {error}"),
            ));
            return report;
        }
    };
    match syntax {
        Syntax::Ubl => check_ubl(&root, invoice, &mut report),
        Syntax::Cii => check_cii(&root, invoice, &mut report),
    }
    report
}

fn fail(report: &mut Report, rule: &str, path: &str, message: impl Into<String>) {
    report.push(ValidationIssue::error(rule, path, message));
}

fn require<'a>(node: &'a Node, name: &str, path: &str, report: &mut Report) -> Option<&'a Node> {
    match node.child(name) {
        Some(child) => Some(child),
        None => {
            fail(
                report,
                "XML-REQ-01",
                &format!("{path}/{name}"),
                format!("the required element {name} is missing"),
            );
            None
        }
    }
}

fn text_of(node: &Node, name: &str, path: &str, report: &mut Report) -> Option<String> {
    require(node, name, path, report).map(|child| child.text.trim().to_string())
}

fn expect_text(node: &Node, name: &str, expected: &str, path: &str, report: &mut Report) {
    if let Some(actual) = text_of(node, name, path, report) {
        if actual != expected {
            fail(
                report,
                "XML-FIG-01",
                &format!("{path}/{name}"),
                format!("{actual:?} does not match the model value {expected:?}"),
            );
        }
    }
}

fn expect_money(
    node: &Node,
    name: &str,
    expected: i64,
    path: &str,
    report: &mut Report,
) -> Option<i64> {
    let text = text_of(node, name, path, report)?;
    let Some(actual) = parse_money(&text) else {
        fail(
            report,
            "XML-DT-01",
            &format!("{path}/{name}"),
            format!("{text:?} is not an amount with two decimals"),
        );
        return None;
    };
    if actual != expected {
        fail(
            report,
            "XML-FIG-02",
            &format!("{path}/{name}"),
            format!(
                "{text} does not match the model amount {}",
                format_money(expected)
            ),
        );
    }
    Some(actual)
}

fn expect_percent(node: &Node, name: &str, expected_bp: u32, path: &str, report: &mut Report) {
    let Some(text) = text_of(node, name, path, report) else {
        return;
    };
    match parse_percent(&text) {
        Some(actual) if actual == expected_bp => {}
        Some(_) => fail(
            report,
            "XML-FIG-03",
            &format!("{path}/{name}"),
            format!(
                "{text} does not match the model rate {}",
                format_percent(expected_bp)
            ),
        ),
        None => fail(
            report,
            "XML-DT-02",
            &format!("{path}/{name}"),
            format!("{text:?} is not a percentage with at most two decimals"),
        ),
    }
}

fn expect_quantity(
    node: &Node,
    name: &str,
    expected_milli: i64,
    unit_code: &str,
    path: &str,
    report: &mut Report,
) {
    let Some(child) = require(node, name, path, report) else {
        return;
    };
    let text = child.text.trim();
    match parse_quantity(text) {
        Some(actual) if actual == expected_milli => {}
        Some(_) => fail(
            report,
            "XML-FIG-04",
            &format!("{path}/{name}"),
            format!(
                "{text} does not match the model quantity {}",
                format_quantity(expected_milli)
            ),
        ),
        None => fail(
            report,
            "XML-DT-03",
            &format!("{path}/{name}"),
            format!("{text:?} is not a quantity with at most three decimals"),
        ),
    }
    match child.attribute("unitCode") {
        Some(actual) if actual == unit_code => {}
        Some(actual) => fail(
            report,
            "XML-CODE-01",
            &format!("{path}/{name}"),
            format!("unit code {actual:?} does not match the model unit {unit_code:?}"),
        ),
        None => fail(
            report,
            "XML-DT-04",
            &format!("{path}/{name}"),
            "a quantity needs a unit code",
        ),
    }
}

fn check_sequence(node: &Node, order: &[&str], path: &str, report: &mut Report) {
    let mut last = 0usize;
    let mut seen_any = false;
    for child in &node.children {
        match order.iter().position(|name| *name == child.name) {
            None => fail(
                report,
                "XML-SEQ-02",
                &format!("{path}/{}", child.name),
                format!("the element {} is not allowed at this position", child.name),
            ),
            Some(index) => {
                if seen_any && index < last {
                    fail(
                        report,
                        "XML-SEQ-01",
                        &format!("{path}/{}", child.name),
                        format!(
                            "the element {} is out of schema order (after {})",
                            child.name, order[last]
                        ),
                    );
                }
                last = index;
                seen_any = true;
            }
        }
    }
}

fn check_currency_attributes(node: &Node, currency: &str, path: &str, report: &mut Report) {
    if let Some(attribute) = node.attribute("currencyID") {
        if attribute != currency {
            fail(
                report,
                "XML-CUR-01",
                path,
                format!(
                    "currencyID {attribute:?} does not match the invoice currency {currency:?}"
                ),
            );
        }
    }
    for child in &node.children {
        check_currency_attributes(child, currency, &format!("{path}/{}", child.name), report);
    }
}

fn check_required_attributes(
    node: &Node,
    expected: &[(&str, &str)],
    path: &str,
    report: &mut Report,
) {
    for (name, value) in expected {
        match node.attribute(name) {
            Some(actual) if actual == *value => {}
            Some(actual) => fail(
                report,
                "XML-NS-01",
                path,
                format!("{name} is {actual:?}, expected {value:?}"),
            ),
            None => fail(
                report,
                "XML-NS-01",
                path,
                format!("the namespace declaration {name} is missing"),
            ),
        }
    }
}

fn check_customization_id(id: &str, path: &str, report: &mut Report) {
    if !id.contains("en16931:2017") {
        fail(
            report,
            "XML-SPEC-01",
            path,
            format!("{id:?} is not an EN 16931 specification identifier"),
        );
    }
}

const UBL_ROOT_ORDER: &[&str] = &[
    "ext:UBLExtensions",
    "cbc:CustomizationID",
    "cbc:ProfileID",
    "cbc:ID",
    "cbc:IssueDate",
    "cbc:DueDate",
    "cbc:InvoiceTypeCode",
    "cbc:CreditNoteTypeCode",
    "cbc:Note",
    "cbc:DocumentCurrencyCode",
    "cbc:BuyerReference",
    "cac:AccountingSupplierParty",
    "cac:AccountingCustomerParty",
    "cac:PaymentMeans",
    "cac:AllowanceCharge",
    "cac:TaxTotal",
    "cac:LegalMonetaryTotal",
    "cac:InvoiceLine",
    "cac:CreditNoteLine",
];

const UBL_MONETARY_ORDER: &[&str] = &[
    "cbc:LineExtensionAmount",
    "cbc:TaxExclusiveAmount",
    "cbc:TaxInclusiveAmount",
    "cbc:AllowanceTotalAmount",
    "cbc:ChargeTotalAmount",
    "cbc:PrepaidAmount",
    "cbc:PayableRoundingAmount",
    "cbc:PayableAmount",
];

const UBL_LINE_ORDER: &[&str] = &[
    "cbc:ID",
    "cbc:Note",
    "cbc:InvoicedQuantity",
    "cbc:CreditedQuantity",
    "cbc:LineExtensionAmount",
    "cac:AllowanceCharge",
    "cac:Item",
    "cac:Price",
];

const UBL_ITEM_ORDER: &[&str] = &["cbc:Description", "cbc:Name", "cac:ClassifiedTaxCategory"];

const UBL_PARTY_ORDER: &[&str] = &[
    "cbc:EndpointID",
    "cac:PartyName",
    "cac:PostalAddress",
    "cac:PartyTaxScheme",
    "cac:PartyLegalEntity",
];

const UBL_ADDRESS_ORDER: &[&str] = &[
    "cbc:StreetName",
    "cbc:AdditionalStreetName",
    "cbc:CityName",
    "cbc:PostalZone",
    "cac:Country",
];

fn check_ubl(root: &Node, invoice: &Invoice, report: &mut Report) {
    let credit_note = invoice.document_type == DocumentType::CreditNote;
    let expected_root = if credit_note { "CreditNote" } else { "Invoice" };
    if root.name != expected_root {
        fail(
            report,
            "XML-ROOT-01",
            expected_root,
            format!(
                "the root element is {}, expected {expected_root}",
                root.name
            ),
        );
        return;
    }
    check_required_attributes(
        root,
        &[
            (
                "xmlns",
                if credit_note {
                    ubl::CREDIT_NOTE_NAMESPACE
                } else {
                    ubl::INVOICE_NAMESPACE
                },
            ),
            ("xmlns:cac", ubl::CAC_NAMESPACE),
            ("xmlns:cbc", ubl::CBC_NAMESPACE),
        ],
        expected_root,
        report,
    );
    check_sequence(root, UBL_ROOT_ORDER, expected_root, report);

    if let Some(id) = text_of(root, "cbc:CustomizationID", expected_root, report) {
        check_customization_id(&id, &format!("{expected_root}/cbc:CustomizationID"), report);
    }
    expect_text(root, "cbc:ID", &invoice.number, expected_root, report);
    expect_text(
        root,
        "cbc:IssueDate",
        &invoice.issue_date.to_iso(),
        expected_root,
        report,
    );
    match (invoice.due_date, root.child("cbc:DueDate")) {
        (Some(due), Some(node)) => {
            if node.text.trim() != due.to_iso() {
                fail(
                    report,
                    "XML-FIG-05",
                    &format!("{expected_root}/cbc:DueDate"),
                    format!("{} does not match the model due date", node.text.trim()),
                );
            }
        }
        (Some(_), None) => fail(
            report,
            "XML-REQ-02",
            &format!("{expected_root}/cbc:DueDate"),
            "the model has a due date and the document does not",
        ),
        (None, Some(_)) => fail(
            report,
            "XML-FIG-06",
            &format!("{expected_root}/cbc:DueDate"),
            "the document has a due date and the model does not",
        ),
        (None, None) => {}
    }
    expect_text(
        root,
        if credit_note {
            "cbc:CreditNoteTypeCode"
        } else {
            "cbc:InvoiceTypeCode"
        },
        invoice.document_type.code(),
        expected_root,
        report,
    );
    expect_text(
        root,
        "cbc:DocumentCurrencyCode",
        &invoice.currency,
        expected_root,
        report,
    );
    check_currency_attributes(root, &invoice.currency, expected_root, report);

    check_ubl_party(
        root,
        "cac:AccountingSupplierParty",
        &invoice.seller,
        expected_root,
        report,
    );
    check_ubl_party(
        root,
        "cac:AccountingCustomerParty",
        &invoice.buyer,
        expected_root,
        report,
    );

    let totals = invoice.totals();

    let allowance_nodes = root.children_named("cac:AllowanceCharge").count();
    let expected_allowances = invoice.allowances.len() + invoice.charges.len();
    if allowance_nodes != expected_allowances {
        fail(
            report,
            "XML-CARD-01",
            &format!("{expected_root}/cac:AllowanceCharge"),
            format!("{allowance_nodes} allowance or charge elements for {expected_allowances} in the model"),
        );
    }

    if let Some(tax_total) = require(root, "cac:TaxTotal", expected_root, report) {
        let path = format!("{expected_root}/cac:TaxTotal");
        expect_money(
            tax_total,
            "cbc:TaxAmount",
            totals.tax_total_minor,
            &path,
            report,
        );
        let subtotals: Vec<&Node> = tax_total.children_named("cac:TaxSubtotal").collect();
        if subtotals.len() != totals.breakdown.len() {
            fail(
                report,
                "XML-CARD-02",
                &path,
                format!(
                    "{} VAT subtotals for {} VAT groups",
                    subtotals.len(),
                    totals.breakdown.len()
                ),
            );
        }
        for (index, group) in totals.breakdown.iter().enumerate() {
            let Some(subtotal) = subtotals.get(index) else {
                break;
            };
            let subtotal_path = format!("{path}/cac:TaxSubtotal[{index}]");
            expect_money(
                subtotal,
                "cbc:TaxableAmount",
                group.taxable_minor,
                &subtotal_path,
                report,
            );
            expect_money(
                subtotal,
                "cbc:TaxAmount",
                group.tax_minor,
                &subtotal_path,
                report,
            );
            let Some(category) = require(subtotal, "cac:TaxCategory", &subtotal_path, report)
            else {
                continue;
            };
            expect_text(
                category,
                "cbc:ID",
                group.vat_category.code(),
                &subtotal_path,
                report,
            );
            expect_percent(
                category,
                "cbc:Percent",
                group.vat_rate_bp,
                &subtotal_path,
                report,
            );
            if let Some(scheme) = require(category, "cac:TaxScheme", &subtotal_path, report) {
                expect_text(scheme, "cbc:ID", "VAT", &subtotal_path, report);
            }
        }
    }

    if let Some(monetary) = require(root, "cac:LegalMonetaryTotal", expected_root, report) {
        let path = format!("{expected_root}/cac:LegalMonetaryTotal");
        check_sequence(monetary, UBL_MONETARY_ORDER, &path, report);
        expect_money(
            monetary,
            "cbc:LineExtensionAmount",
            totals.line_total_minor,
            &path,
            report,
        );
        expect_money(
            monetary,
            "cbc:TaxExclusiveAmount",
            totals.tax_exclusive_minor,
            &path,
            report,
        );
        expect_money(
            monetary,
            "cbc:TaxInclusiveAmount",
            totals.tax_inclusive_minor,
            &path,
            report,
        );
        expect_money(
            monetary,
            "cbc:PayableAmount",
            totals.payable_minor,
            &path,
            report,
        );
        if totals.allowance_total_minor > 0 {
            expect_money(
                monetary,
                "cbc:AllowanceTotalAmount",
                totals.allowance_total_minor,
                &path,
                report,
            );
        }
        if totals.rounding_minor != 0 {
            expect_money(
                monetary,
                "cbc:PayableRoundingAmount",
                totals.rounding_minor,
                &path,
                report,
            );
        }
        if totals.prepaid_minor > 0 {
            expect_money(
                monetary,
                "cbc:PrepaidAmount",
                totals.prepaid_minor,
                &path,
                report,
            );
        }
    }

    let line_name = if credit_note {
        "cac:CreditNoteLine"
    } else {
        "cac:InvoiceLine"
    };
    let quantity_name = if credit_note {
        "cbc:CreditedQuantity"
    } else {
        "cbc:InvoicedQuantity"
    };
    let lines: Vec<&Node> = root.children_named(line_name).collect();
    if lines.len() != invoice.lines.len() {
        fail(
            report,
            "XML-CARD-03",
            line_name,
            format!(
                "{} line elements for {} model lines",
                lines.len(),
                invoice.lines.len()
            ),
        );
    }
    for (index, line) in invoice.lines.iter().enumerate() {
        let Some(node) = lines.get(index) else {
            break;
        };
        let path = format!("{line_name}[{index}]");
        check_sequence(node, UBL_LINE_ORDER, &path, report);
        expect_text(node, "cbc:ID", &line.id, &path, report);
        expect_quantity(
            node,
            quantity_name,
            line.quantity_milli,
            &line.unit_code,
            &path,
            report,
        );
        expect_money(
            node,
            "cbc:LineExtensionAmount",
            line.net_minor(),
            &path,
            report,
        );
        if let Some(item) = require(node, "cac:Item", &path, report) {
            check_sequence(item, UBL_ITEM_ORDER, &path, report);
            expect_text(item, "cbc:Name", &line.name, &path, report);
            if let Some(category) = require(item, "cac:ClassifiedTaxCategory", &path, report) {
                expect_text(category, "cbc:ID", line.vat_category.code(), &path, report);
                expect_percent(category, "cbc:Percent", line.vat_rate_bp, &path, report);
            }
        }
        if let Some(price) = require(node, "cac:Price", &path, report) {
            expect_money(
                price,
                "cbc:PriceAmount",
                line.unit_price_minor,
                &path,
                report,
            );
        }
    }
}

fn check_ubl_party(
    root: &Node,
    element: &str,
    party: &Party,
    root_path: &str,
    report: &mut Report,
) {
    let path = format!("{root_path}/{element}");
    let Some(wrapper) = require(root, element, root_path, report) else {
        return;
    };
    let Some(node) = require(wrapper, "cac:Party", &path, report) else {
        return;
    };
    check_sequence(node, UBL_PARTY_ORDER, &path, report);
    let Some(address) = require(node, "cac:PostalAddress", &path, report) else {
        return;
    };
    check_sequence(address, UBL_ADDRESS_ORDER, &path, report);
    expect_text(
        address,
        "cbc:StreetName",
        &party.address.line1,
        &path,
        report,
    );
    expect_text(address, "cbc:CityName", &party.address.city, &path, report);
    expect_text(
        address,
        "cbc:PostalZone",
        &party.address.postcode,
        &path,
        report,
    );
    if let Some(country) = require(address, "cac:Country", &path, report) {
        expect_text(
            country,
            "cbc:IdentificationCode",
            &party.address.country,
            &path,
            report,
        );
    }
    if let Some(vat_id) = &party.vat_id {
        if let Some(tax_scheme) = node.child("cac:PartyTaxScheme") {
            expect_text(tax_scheme, "cbc:CompanyID", vat_id, &path, report);
        }
    }
    let Some(legal) = require(node, "cac:PartyLegalEntity", &path, report) else {
        return;
    };
    expect_text(legal, "cbc:RegistrationName", &party.name, &path, report);
}

const CII_ROOT_ORDER: &[&str] = &[
    "rsm:ExchangedDocumentContext",
    "rsm:ExchangedDocument",
    "rsm:SupplyChainTradeTransaction",
];

const CII_DOCUMENT_ORDER: &[&str] = &[
    "ram:ID",
    "ram:TypeCode",
    "ram:IssueDateTime",
    "ram:IncludedNote",
];

const CII_TRANSACTION_ORDER: &[&str] = &[
    "ram:IncludedSupplyChainTradeLineItem",
    "ram:ApplicableHeaderTradeAgreement",
    "ram:ApplicableHeaderTradeDelivery",
    "ram:ApplicableHeaderTradeSettlement",
];

const CII_AGREEMENT_ORDER: &[&str] = &[
    "ram:BuyerReference",
    "ram:SellerTradeParty",
    "ram:BuyerTradeParty",
];

const CII_SETTLEMENT_ORDER: &[&str] = &[
    "ram:CreditorReferenceID",
    "ram:PaymentReference",
    "ram:TaxCurrencyCode",
    "ram:InvoiceCurrencyCode",
    "ram:SpecifiedTradeSettlementPaymentMeans",
    "ram:ApplicableTradeTax",
    "ram:BillingSpecifiedPeriod",
    "ram:SpecifiedTradeAllowanceCharge",
    "ram:SpecifiedTradePaymentTerms",
    "ram:SpecifiedTradeSettlementHeaderMonetarySummation",
    "ram:InvoiceReferencedDocument",
    "ram:ReceivableSpecifiedTradeAccountingAccount",
];

const CII_SUMMATION_ORDER: &[&str] = &[
    "ram:LineTotalAmount",
    "ram:ChargeTotalAmount",
    "ram:AllowanceTotalAmount",
    "ram:TaxBasisTotalAmount",
    "ram:TaxTotalAmount",
    "ram:RoundingAmount",
    "ram:GrandTotalAmount",
    "ram:TotalPrepaidAmount",
    "ram:DuePayableAmount",
    "ram:TotalDiscountAmount",
];

fn check_cii(root: &Node, invoice: &Invoice, report: &mut Report) {
    if root.name != "rsm:CrossIndustryInvoice" {
        fail(
            report,
            "XML-ROOT-01",
            "rsm:CrossIndustryInvoice",
            format!(
                "the root element is {}, expected rsm:CrossIndustryInvoice",
                root.name
            ),
        );
        return;
    }
    check_required_attributes(
        root,
        &[
            ("xmlns:rsm", cii::CII_NAMESPACE),
            ("xmlns:ram", cii::RAM_NAMESPACE),
            ("xmlns:udt", cii::UDT_NAMESPACE),
        ],
        "rsm:CrossIndustryInvoice",
        report,
    );
    check_sequence(root, CII_ROOT_ORDER, "rsm:CrossIndustryInvoice", report);

    if let Some(context) = require(
        root,
        "rsm:ExchangedDocumentContext",
        "rsm:CrossIndustryInvoice",
        report,
    ) {
        let path = "rsm:CrossIndustryInvoice/rsm:ExchangedDocumentContext";
        if let Some(parameter) = require(
            context,
            "ram:GuidelineSpecifiedDocumentContextParameter",
            path,
            report,
        ) {
            if let Some(id) = text_of(
                parameter,
                "ram:ID",
                &format!("{path}/ram:GuidelineSpecifiedDocumentContextParameter"),
                report,
            ) {
                check_customization_id(
                    &id,
                    &format!("{path}/ram:GuidelineSpecifiedDocumentContextParameter/ram:ID"),
                    report,
                );
            }
        }
    }

    let document_path = "rsm:CrossIndustryInvoice/rsm:ExchangedDocument";
    if let Some(exchanged) = require(
        root,
        "rsm:ExchangedDocument",
        "rsm:CrossIndustryInvoice",
        report,
    ) {
        check_sequence(exchanged, CII_DOCUMENT_ORDER, document_path, report);
        expect_text(exchanged, "ram:ID", &invoice.number, document_path, report);
        expect_text(
            exchanged,
            "ram:TypeCode",
            invoice.document_type.code(),
            document_path,
            report,
        );
        if let Some(date_time) = require(exchanged, "ram:IssueDateTime", document_path, report) {
            let path = format!("{document_path}/ram:IssueDateTime");
            if let Some(node) = require(date_time, "udt:DateTimeString", &path, report) {
                if node.attribute("format") != Some("102") {
                    fail(
                        report,
                        "XML-FMT-01",
                        &path,
                        "the issue date needs format=\"102\"",
                    );
                }
                if node.text.trim() != invoice.issue_date.to_compact() {
                    fail(
                        report,
                        "XML-FIG-07",
                        &path,
                        format!("{} does not match the model issue date", node.text.trim()),
                    );
                }
            }
        }
    }

    let transaction_path = "rsm:CrossIndustryInvoice/rsm:SupplyChainTradeTransaction";
    let Some(transaction) = require(
        root,
        "rsm:SupplyChainTradeTransaction",
        "rsm:CrossIndustryInvoice",
        report,
    ) else {
        return;
    };
    check_sequence(transaction, CII_TRANSACTION_ORDER, transaction_path, report);

    let totals = invoice.totals();
    let items: Vec<&Node> = transaction
        .children_named("ram:IncludedSupplyChainTradeLineItem")
        .collect();
    if items.len() != invoice.lines.len() {
        fail(
            report,
            "XML-CARD-03",
            transaction_path,
            format!(
                "{} line items for {} model lines",
                items.len(),
                invoice.lines.len()
            ),
        );
    }
    for (index, line) in invoice.lines.iter().enumerate() {
        let Some(node) = items.get(index) else {
            break;
        };
        let path = format!("{transaction_path}/ram:IncludedSupplyChainTradeLineItem[{index}]");
        if let Some(document_line) =
            require(node, "ram:AssociatedDocumentLineDocument", &path, report)
        {
            expect_text(document_line, "ram:LineID", &line.id, &path, report);
        }
        if let Some(product) = require(node, "ram:SpecifiedTradeProduct", &path, report) {
            expect_text(product, "ram:Name", &line.name, &path, report);
        }
        if let Some(agreement) = require(node, "ram:SpecifiedLineTradeAgreement", &path, report) {
            if let Some(price) = require(agreement, "ram:NetPriceProductTradePrice", &path, report)
            {
                expect_money(
                    price,
                    "ram:ChargeAmount",
                    line.unit_price_minor,
                    &path,
                    report,
                );
            }
        }
        if let Some(delivery) = require(node, "ram:SpecifiedLineTradeDelivery", &path, report) {
            expect_quantity(
                delivery,
                "ram:BilledQuantity",
                line.quantity_milli,
                &line.unit_code,
                &path,
                report,
            );
        }
        if let Some(settlement) = require(node, "ram:SpecifiedLineTradeSettlement", &path, report) {
            if let Some(tax) = require(settlement, "ram:ApplicableTradeTax", &path, report) {
                expect_text(tax, "ram:TypeCode", "VAT", &path, report);
                expect_text(
                    tax,
                    "ram:CategoryCode",
                    line.vat_category.code(),
                    &path,
                    report,
                );
                expect_percent(
                    tax,
                    "ram:RateApplicablePercent",
                    line.vat_rate_bp,
                    &path,
                    report,
                );
            }
            if let Some(summation) = require(
                settlement,
                "ram:SpecifiedTradeSettlementLineMonetarySummation",
                &path,
                report,
            ) {
                expect_money(
                    summation,
                    "ram:LineTotalAmount",
                    line.net_minor(),
                    &path,
                    report,
                );
            }
        }
    }

    let agreement_path = format!("{transaction_path}/ram:ApplicableHeaderTradeAgreement");
    if let Some(agreement) = require(
        transaction,
        "ram:ApplicableHeaderTradeAgreement",
        transaction_path,
        report,
    ) {
        check_sequence(agreement, CII_AGREEMENT_ORDER, &agreement_path, report);
        check_cii_party(
            agreement,
            "ram:SellerTradeParty",
            &invoice.seller,
            &agreement_path,
            report,
        );
        check_cii_party(
            agreement,
            "ram:BuyerTradeParty",
            &invoice.buyer,
            &agreement_path,
            report,
        );
    }
    // The delivery element carries no value in this crate, but the CII binding
    // requires it to be present, so it is required here too.
    let _delivery = require(
        transaction,
        "ram:ApplicableHeaderTradeDelivery",
        transaction_path,
        report,
    );

    let settlement_path = format!("{transaction_path}/ram:ApplicableHeaderTradeSettlement");
    let Some(settlement) = require(
        transaction,
        "ram:ApplicableHeaderTradeSettlement",
        transaction_path,
        report,
    ) else {
        return;
    };
    check_sequence(settlement, CII_SETTLEMENT_ORDER, &settlement_path, report);
    expect_text(
        settlement,
        "ram:InvoiceCurrencyCode",
        &invoice.currency,
        &settlement_path,
        report,
    );
    check_currency_attributes(settlement, &invoice.currency, &settlement_path, report);

    let taxes: Vec<&Node> = settlement
        .children_named("ram:ApplicableTradeTax")
        .collect();
    if taxes.len() != totals.breakdown.len() {
        fail(
            report,
            "XML-CARD-02",
            &settlement_path,
            format!(
                "{} VAT groups for {} in the model",
                taxes.len(),
                totals.breakdown.len()
            ),
        );
    }
    for (index, group) in totals.breakdown.iter().enumerate() {
        let Some(tax) = taxes.get(index) else {
            break;
        };
        let path = format!("{settlement_path}/ram:ApplicableTradeTax[{index}]");
        expect_money(tax, "ram:CalculatedAmount", group.tax_minor, &path, report);
        expect_text(tax, "ram:TypeCode", "VAT", &path, report);
        expect_money(tax, "ram:BasisAmount", group.taxable_minor, &path, report);
        expect_text(
            tax,
            "ram:CategoryCode",
            group.vat_category.code(),
            &path,
            report,
        );
        expect_percent(
            tax,
            "ram:RateApplicablePercent",
            group.vat_rate_bp,
            &path,
            report,
        );
    }

    let allowances = settlement
        .children_named("ram:SpecifiedTradeAllowanceCharge")
        .count();
    let expected_allowances = invoice.allowances.len() + invoice.charges.len();
    if allowances != expected_allowances {
        fail(
            report,
            "XML-CARD-01",
            &settlement_path,
            format!(
                "{allowances} allowance or charge elements for {expected_allowances} in the model"
            ),
        );
    }

    let summation_path =
        format!("{settlement_path}/ram:SpecifiedTradeSettlementHeaderMonetarySummation");
    if let Some(summation) = require(
        settlement,
        "ram:SpecifiedTradeSettlementHeaderMonetarySummation",
        &settlement_path,
        report,
    ) {
        check_sequence(summation, CII_SUMMATION_ORDER, &summation_path, report);
        expect_money(
            summation,
            "ram:LineTotalAmount",
            totals.line_total_minor,
            &summation_path,
            report,
        );
        expect_money(
            summation,
            "ram:TaxBasisTotalAmount",
            totals.tax_exclusive_minor,
            &summation_path,
            report,
        );
        expect_money(
            summation,
            "ram:TaxTotalAmount",
            totals.tax_total_minor,
            &summation_path,
            report,
        );
        expect_money(
            summation,
            "ram:GrandTotalAmount",
            totals.tax_inclusive_minor,
            &summation_path,
            report,
        );
        expect_money(
            summation,
            "ram:DuePayableAmount",
            totals.payable_minor,
            &summation_path,
            report,
        );
        if totals.rounding_minor != 0 {
            expect_money(
                summation,
                "ram:RoundingAmount",
                totals.rounding_minor,
                &summation_path,
                report,
            );
        }
    }

    let references = settlement
        .children_named("ram:InvoiceReferencedDocument")
        .count();
    if references != invoice.preceding_invoices.len() {
        fail(
            report,
            "XML-CARD-04",
            &settlement_path,
            format!(
                "{references} preceding invoice references for {} in the model",
                invoice.preceding_invoices.len()
            ),
        );
    }
    for (index, reference) in invoice.preceding_invoices.iter().enumerate() {
        if let Some(node) = settlement
            .children_named("ram:InvoiceReferencedDocument")
            .nth(index)
        {
            expect_text(
                node,
                "ram:IssuerAssignedID",
                reference,
                &settlement_path,
                report,
            );
        }
    }
}

fn check_cii_party(
    agreement: &Node,
    element: &str,
    party: &Party,
    path: &str,
    report: &mut Report,
) {
    let Some(node) = require(agreement, element, path, report) else {
        return;
    };
    let path = format!("{path}/{element}");
    expect_text(node, "ram:Name", &party.name, &path, report);
    let Some(address) = require(node, "ram:PostalTradeAddress", &path, report) else {
        return;
    };
    expect_text(address, "ram:LineOne", &party.address.line1, &path, report);
    expect_text(address, "ram:CityName", &party.address.city, &path, report);
    expect_text(
        address,
        "ram:PostcodeCode",
        &party.address.postcode,
        &path,
        report,
    );
    expect_text(
        address,
        "ram:CountryID",
        &party.address.country,
        &path,
        report,
    );
    if let Some(vat_id) = &party.vat_id {
        if let Some(registration) = node.child("ram:SpecifiedTaxRegistration") {
            expect_text(registration, "ram:ID", vat_id, &path, report);
        }
    }
}

/// Parse an amount with exactly two decimals into minor units.
pub fn parse_money(text: &str) -> Option<i64> {
    let text = text.trim();
    let (sign, rest) = match text.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, text),
    };
    let (whole, fraction) = rest.split_once('.')?;
    if whole.is_empty()
        || !whole.chars().all(|character| character.is_ascii_digit())
        || fraction.len() != 2
        || !fraction.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    let fraction: i64 = fraction.parse().ok()?;
    Some(sign * whole.checked_mul(100)?.checked_add(fraction)?)
}

/// Parse a quantity with at most three decimals into thousandths.
pub fn parse_quantity(text: &str) -> Option<i64> {
    let text = text.trim();
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    if whole.is_empty()
        || !whole.chars().all(|character| character.is_ascii_digit())
        || fraction.len() > 3
        || !fraction.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    let mut fraction_text = fraction.to_string();
    while fraction_text.len() < 3 {
        fraction_text.push('0');
    }
    let fraction: i64 = fraction_text.parse().ok()?;
    whole.checked_mul(1_000)?.checked_add(fraction)
}

/// Parse a percentage with at most two decimals into basis points.
pub fn parse_percent(text: &str) -> Option<u32> {
    let text = text.trim();
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    if whole.is_empty()
        || !whole.chars().all(|character| character.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    let whole: u32 = whole.parse().ok()?;
    let mut fraction_text = fraction.to_string();
    while fraction_text.len() < 2 {
        fraction_text.push('0');
    }
    let fraction: u32 = fraction_text.parse().ok()?;
    whole.checked_mul(100)?.checked_add(fraction)
}

/// Parse a `YYYY-MM-DD` date.
pub fn parse_date(text: &str) -> Option<Date> {
    let text = text.trim();
    let mut parts = text.split('-');
    let year = parts.next()?;
    let month = parts.next()?;
    let day = parts.next()?;
    if parts.next().is_some()
        || year.len() != 4
        || month.len() != 2
        || day.len() != 2
        || !year.chars().all(|character| character.is_ascii_digit())
        || !month.chars().all(|character| character.is_ascii_digit())
        || !day.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    Date::new(year.parse().ok()?, month.parse().ok()?, day.parse().ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Address, InvoiceLine, Party, VatCategory};

    fn invoice() -> Invoice {
        Invoice {
            number: "INV-9".to_string(),
            issue_date: Date::new(2026, 2, 3).expect("date"),
            due_date: None,
            document_type: DocumentType::Invoice,
            currency: "EUR".to_string(),
            seller: Party::new(
                "Acme SL",
                Address::new("Calle Mayor 1", None, "Madrid", "28013", "ES").expect("address"),
            )
            .expect("party"),
            buyer: Party::new(
                "Customer",
                Address::new("Calle Menor 2", None, "Madrid", "28014", "ES").expect("address"),
            )
            .expect("party"),
            lines: vec![InvoiceLine::new(
                "1",
                "Espresso",
                1_000,
                "C62",
                250,
                VatCategory::Standard,
                2_100,
            )
            .expect("line")],
            allowances: Vec::new(),
            charges: Vec::new(),
            prepaid_minor: 0,
            rounding_minor: 0,
            payment_means: None,
            payment_reference: None,
            buyer_reference: None,
            note: None,
            preceding_invoices: Vec::new(),
        }
    }

    #[test]
    fn a_freshly_serialized_document_validates_in_both_syntaxes() {
        let invoice = invoice();
        for syntax in [Syntax::Ubl, Syntax::Cii] {
            let document = match syntax {
                Syntax::Ubl => ubl::serialize(&invoice),
                Syntax::Cii => cii::serialize(&invoice),
            };
            let report = validate_document(&document, &invoice, syntax);
            assert!(report.valid, "{}: {}", syntax.id(), report.render());
            assert_eq!(report.error_count(), 0);
        }
    }

    #[test]
    fn a_tampered_figure_is_caught() {
        let invoice = invoice();
        let document = ubl::serialize(&invoice).replace("2.50", "2.60");
        let report = validate_document(&document, &invoice, Syntax::Ubl);
        assert!(!report.valid);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.rule.starts_with("XML-FIG")));
    }

    #[test]
    fn a_tampered_rate_and_a_broken_document_are_caught() {
        let invoice = invoice();
        let document = cii::serialize(&invoice).replace(
            "<ram:RateApplicablePercent>21.00</ram:RateApplicablePercent>",
            "<ram:RateApplicablePercent>7.50</ram:RateApplicablePercent>",
        );
        let report = validate_document(&document, &invoice, Syntax::Cii);
        assert!(!report.valid);

        let report = validate_document("<Invoice>", &invoice, Syntax::Ubl);
        assert!(!report.valid);
        assert_eq!(report.issues[0].rule, "XML-01");
    }

    #[test]
    fn datatypes_round_trip_through_the_parsers() {
        assert_eq!(parse_money("12.34"), Some(1_234));
        assert_eq!(parse_money("-0.05"), Some(-5));
        assert_eq!(parse_money("12.3"), None);
        assert_eq!(parse_money("12"), None);
        assert_eq!(parse_quantity("2"), Some(2_000));
        assert_eq!(parse_quantity("1.5"), Some(1_500));
        assert_eq!(parse_quantity("1.2345"), None);
        assert_eq!(parse_percent("21.00"), Some(2_100));
        assert_eq!(parse_percent("7.5"), Some(750));
        assert_eq!(parse_date("2026-02-03"), Date::new(2026, 2, 3).ok());
        assert_eq!(parse_date("2026-02-30"), None);
        assert_eq!(parse_date("2026-2-3"), None);
    }

    #[test]
    fn report_text_is_stable() {
        let invoice = invoice();
        let mut invoice = invoice;
        invoice.number = String::new();
        let report = validate_document(&ubl::serialize(&invoice), &invoice, Syntax::Ubl);
        assert!(!report.valid);
        assert!(report.render().contains("error"));
        assert_eq!(report.error_count(), report.issues.len());
    }
}
