// SPDX-License-Identifier: Apache-2.0

//! UBL 2.1 Invoice and CreditNote serialization.
//!
//! The element order follows the UBL 2.1 schema sequence (UBL-Invoice-2.1 /
//! UBL-CreditNote-2.1), which is what makes the output acceptable to a
//! schema-validating receiver. Amounts are formatted with two decimals and carry
//! `currencyID`; quantities carry a UN/ECE Recommendation 20 `unitCode`.

use crate::model::{
    format_money, format_percent, format_quantity, AllowanceCharge, Invoice, Party,
};
use crate::profiles::CountryProfile;
use crate::validate::Syntax;
use crate::xml::Writer;
use crate::SPECIFICATION_ID;

/// UBL 2.1 Invoice namespace.
pub const INVOICE_NAMESPACE: &str = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";

/// UBL 2.1 CreditNote namespace.
pub const CREDIT_NOTE_NAMESPACE: &str = "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2";

/// UBL common aggregate components namespace.
pub const CAC_NAMESPACE: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";

/// UBL common basic components namespace.
pub const CBC_NAMESPACE: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";

/// UBL extension component namespace.
pub const EXT_NAMESPACE: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";

/// Serialize an invoice as UBL 2.1.
pub fn serialize(invoice: &Invoice) -> String {
    build(invoice, None)
}

/// Serialize as UBL 2.1 under a country profile.
///
pub fn serialize_with(invoice: &Invoice, profile: &dyn CountryProfile) -> Result<String, String> {
    let document = build(invoice, Some(profile));
    profile.wrap(Syntax::Ubl, document)
}

fn build(invoice: &Invoice, profile: Option<&dyn CountryProfile>) -> String {
    let credit_note = invoice.document_type == crate::model::DocumentType::CreditNote;
    let root = if credit_note { "CreditNote" } else { "Invoice" };
    let extension = profile.and_then(|profile| profile.extension(invoice));
    let mut attributes: Vec<(&str, &str)> = vec![
        (
            "xmlns",
            if credit_note {
                CREDIT_NOTE_NAMESPACE
            } else {
                INVOICE_NAMESPACE
            },
        ),
        ("xmlns:cac", CAC_NAMESPACE),
        ("xmlns:cbc", CBC_NAMESPACE),
    ];
    let prefix_attribute = extension
        .as_ref()
        .map(|extension| format!("xmlns:{}", extension.prefix));
    if extension.is_some() {
        attributes.push(("xmlns:ext", EXT_NAMESPACE));
    }
    if let (Some(extension), Some(prefix_attribute)) = (&extension, &prefix_attribute) {
        attributes.push((prefix_attribute.as_str(), extension.namespace.as_str()));
    }

    let mut writer = Writer::new();
    writer.open(root, &attributes);

    if let (Some(extension), Some(_)) = (&extension, &prefix_attribute) {
        let element = format!("{}:{}", extension.prefix, extension.name);
        writer.open("ext:UBLExtensions", &[]);
        writer.open("ext:UBLExtension", &[]);
        writer.open("ext:ExtensionContent", &[]);
        writer.open(&element, &[]);
        for (name, text) in &extension.children {
            writer.element(name, &[], text);
        }
        writer.close(&element);
        writer.close("ext:ExtensionContent");
        writer.close("ext:UBLExtension");
        writer.close("ext:UBLExtensions");
    }

    writer.element(
        "cbc:CustomizationID",
        &[],
        profile.map_or(SPECIFICATION_ID, |profile| profile.customization_id()),
    );
    if let Some(profile) = profile {
        if let Some(profile_id) = profile.profile_id() {
            writer.element("cbc:ProfileID", &[], profile_id);
        }
    }
    writer.element("cbc:ID", &[], &invoice.number);
    writer.element("cbc:IssueDate", &[], &invoice.issue_date.to_iso());
    if let Some(due) = invoice.due_date {
        writer.element("cbc:DueDate", &[], &due.to_iso());
    }
    writer.element(
        if credit_note {
            "cbc:CreditNoteTypeCode"
        } else {
            "cbc:InvoiceTypeCode"
        },
        &[],
        invoice.document_type.code(),
    );
    if let Some(note) = &invoice.note {
        writer.element("cbc:Note", &[], note);
    }
    writer.element("cbc:DocumentCurrencyCode", &[], &invoice.currency);
    if let Some(reference) = &invoice.buyer_reference {
        writer.element("cbc:BuyerReference", &[], reference);
    }

    writer.open("cac:AccountingSupplierParty", &[]);
    writer.open("cac:Party", &[]);
    party(&mut writer, &invoice.seller);
    writer.close("cac:Party");
    writer.close("cac:AccountingSupplierParty");

    writer.open("cac:AccountingCustomerParty", &[]);
    writer.open("cac:Party", &[]);
    party(&mut writer, &invoice.buyer);
    writer.close("cac:Party");
    writer.close("cac:AccountingCustomerParty");

    if let Some(means) = &invoice.payment_means {
        writer.open("cac:PaymentMeans", &[]);
        writer.element("cbc:PaymentMeansCode", &[], &means.code);
        if let Some(reference) = &invoice.payment_reference {
            writer.element("cbc:PaymentID", &[], reference);
        }
        if let Some(instruction) = &means.instruction {
            writer.element("cbc:InstructionNote", &[], instruction);
        }
        writer.close("cac:PaymentMeans");
    } else if let Some(reference) = &invoice.payment_reference {
        writer.open("cac:PaymentMeans", &[]);
        writer.element("cbc:PaymentMeansCode", &[], "30");
        writer.element("cbc:PaymentID", &[], reference);
        writer.close("cac:PaymentMeans");
    }

    for entry in &invoice.allowances {
        allowance_charge(&mut writer, entry, false, &invoice.currency);
    }
    for entry in &invoice.charges {
        allowance_charge(&mut writer, entry, true, &invoice.currency);
    }

    let totals = invoice.totals();
    writer.open("cac:TaxTotal", &[]);
    writer.element(
        "cbc:TaxAmount",
        &[("currencyID", &invoice.currency)],
        &format_money(totals.tax_total_minor),
    );
    for group in &totals.breakdown {
        writer.open("cac:TaxSubtotal", &[]);
        writer.element(
            "cbc:TaxableAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(group.taxable_minor),
        );
        writer.element(
            "cbc:TaxAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(group.tax_minor),
        );
        writer.open("cac:TaxCategory", &[]);
        writer.element("cbc:ID", &[], group.vat_category.code());
        writer.element("cbc:Percent", &[], &format_percent(group.vat_rate_bp));
        writer.open("cac:TaxScheme", &[]);
        writer.element("cbc:ID", &[], "VAT");
        writer.close("cac:TaxScheme");
        writer.close("cac:TaxCategory");
        writer.close("cac:TaxSubtotal");
    }
    writer.close("cac:TaxTotal");

    writer.open("cac:LegalMonetaryTotal", &[]);
    writer.element(
        "cbc:LineExtensionAmount",
        &[("currencyID", &invoice.currency)],
        &format_money(totals.line_total_minor),
    );
    writer.element(
        "cbc:TaxExclusiveAmount",
        &[("currencyID", &invoice.currency)],
        &format_money(totals.tax_exclusive_minor),
    );
    writer.element(
        "cbc:TaxInclusiveAmount",
        &[("currencyID", &invoice.currency)],
        &format_money(totals.tax_inclusive_minor),
    );
    if totals.allowance_total_minor > 0 {
        writer.element(
            "cbc:AllowanceTotalAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(totals.allowance_total_minor),
        );
    }
    if totals.charge_total_minor > 0 {
        writer.element(
            "cbc:ChargeTotalAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(totals.charge_total_minor),
        );
    }
    if totals.prepaid_minor > 0 {
        writer.element(
            "cbc:PrepaidAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(totals.prepaid_minor),
        );
    }
    if totals.rounding_minor != 0 {
        writer.element(
            "cbc:PayableRoundingAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(totals.rounding_minor),
        );
    }
    writer.element(
        "cbc:PayableAmount",
        &[("currencyID", &invoice.currency)],
        &format_money(totals.payable_minor),
    );
    writer.close("cac:LegalMonetaryTotal");

    for line in &invoice.lines {
        let element = if credit_note {
            "cac:CreditNoteLine"
        } else {
            "cac:InvoiceLine"
        };
        writer.open(element, &[]);
        writer.element("cbc:ID", &[], &line.id);
        if let Some(description) = &line.description {
            writer.element("cbc:Note", &[], description);
        }
        writer.element(
            if credit_note {
                "cbc:CreditedQuantity"
            } else {
                "cbc:InvoicedQuantity"
            },
            &[("unitCode", &line.unit_code)],
            &format_quantity(line.quantity_milli),
        );
        writer.element(
            "cbc:LineExtensionAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(line.net_minor()),
        );
        if line.allowance_minor > 0 {
            let allowance = AllowanceCharge {
                reason: line
                    .allowance_reason
                    .clone()
                    .unwrap_or_else(|| "Line discount".to_string()),
                amount_minor: line.allowance_minor,
                percent_bp: None,
                base_minor: Some(line.gross_minor()),
                vat_category: line.vat_category,
                vat_rate_bp: line.vat_rate_bp,
            };
            allowance_charge(&mut writer, &allowance, false, &invoice.currency);
        }
        writer.open("cac:Item", &[]);
        if let Some(description) = &line.description {
            writer.element("cbc:Description", &[], description);
        }
        writer.element("cbc:Name", &[], &line.name);
        writer.open("cac:ClassifiedTaxCategory", &[]);
        writer.element("cbc:ID", &[], line.vat_category.code());
        writer.element("cbc:Percent", &[], &format_percent(line.vat_rate_bp));
        writer.open("cac:TaxScheme", &[]);
        writer.element("cbc:ID", &[], "VAT");
        writer.close("cac:TaxScheme");
        writer.close("cac:ClassifiedTaxCategory");
        writer.close("cac:Item");
        writer.open("cac:Price", &[]);
        writer.element(
            "cbc:PriceAmount",
            &[("currencyID", &invoice.currency)],
            &format_money(line.unit_price_minor),
        );
        writer.close("cac:Price");
        writer.close(element);
    }

    writer.close(root);
    writer.finish()
}

fn party(writer: &mut Writer, party: &Party) {
    if let Some((endpoint, scheme)) = &party.endpoint {
        writer.element("cbc:EndpointID", &[("schemeID", scheme)], endpoint);
    }
    if let Some(trading_name) = &party.trading_name {
        writer.open("cac:PartyName", &[]);
        writer.element("cbc:Name", &[], trading_name);
        writer.close("cac:PartyName");
    }
    writer.open("cac:PostalAddress", &[]);
    writer.element("cbc:StreetName", &[], &party.address.line1);
    if let Some(line2) = &party.address.line2 {
        writer.element("cbc:AdditionalStreetName", &[], line2);
    }
    writer.element("cbc:CityName", &[], &party.address.city);
    writer.element("cbc:PostalZone", &[], &party.address.postcode);
    writer.open("cac:Country", &[]);
    writer.element("cbc:IdentificationCode", &[], &party.address.country);
    writer.close("cac:Country");
    writer.close("cac:PostalAddress");
    if let Some(vat_id) = &party.vat_id {
        writer.open("cac:PartyTaxScheme", &[]);
        writer.element("cbc:CompanyID", &[], vat_id);
        writer.open("cac:TaxScheme", &[]);
        writer.element("cbc:ID", &[], "VAT");
        writer.close("cac:TaxScheme");
        writer.close("cac:PartyTaxScheme");
    }
    writer.open("cac:PartyLegalEntity", &[]);
    writer.element("cbc:RegistrationName", &[], &party.name);
    if let Some((id, _scheme)) = &party.legal_id {
        writer.element("cbc:CompanyID", &[], id);
    }
    writer.close("cac:PartyLegalEntity");
}

fn allowance_charge(writer: &mut Writer, entry: &AllowanceCharge, is_charge: bool, currency: &str) {
    writer.open("cac:AllowanceCharge", &[]);
    writer.element(
        "cbc:ChargeIndicator",
        &[],
        if is_charge { "true" } else { "false" },
    );
    writer.element("cbc:AllowanceChargeReason", &[], &entry.reason);
    writer.element(
        "cbc:Amount",
        &[("currencyID", currency)],
        &format_money(entry.amount_minor),
    );
    if let Some(base) = entry.base_minor {
        writer.element(
            "cbc:BaseAmount",
            &[("currencyID", currency)],
            &format_money(base),
        );
    }
    writer.open("cac:TaxCategory", &[]);
    writer.element("cbc:ID", &[], entry.vat_category.code());
    writer.element("cbc:Percent", &[], &format_percent(entry.vat_rate_bp));
    writer.open("cac:TaxScheme", &[]);
    writer.element("cbc:ID", &[], "VAT");
    writer.close("cac:TaxScheme");
    writer.close("cac:TaxCategory");
    writer.close("cac:AllowanceCharge");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Address, Date, DocumentType, Invoice, InvoiceLine, Party, VatCategory};
    use crate::xml;

    fn sample() -> Invoice {
        Invoice {
            number: "INV-7".to_string(),
            issue_date: Date::new(2026, 3, 1).expect("date"),
            due_date: Some(Date::new(2026, 3, 31).expect("date")),
            document_type: DocumentType::Invoice,
            currency: "EUR".to_string(),
            seller: Party::new(
                "Acme SL",
                Address::new("Calle Mayor 1", None, "Madrid", "28013", "ES").expect("address"),
            )
            .expect("party")
            .with_vat_id("ESA12345674"),
            buyer: Party::new(
                "Customer",
                Address::new("Calle Menor 2", None, "Madrid", "28014", "ES").expect("address"),
            )
            .expect("party"),
            lines: vec![InvoiceLine::new(
                "1",
                "Espresso",
                2_000,
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
    fn serialization_is_stable_and_well_formed() {
        let invoice = sample();
        let first = serialize(&invoice);
        let second = serialize(&invoice);
        assert_eq!(first, second);
        let root = xml::parse(&first).expect("well formed");
        assert_eq!(root.name, "Invoice");
        assert_eq!(root.attribute("xmlns"), Some(INVOICE_NAMESPACE));
        assert_eq!(
            root.child_text("cbc:CustomizationID"),
            Some(SPECIFICATION_ID)
        );
        assert_eq!(root.child_text("cbc:ID"), Some("INV-7"));
        assert_eq!(root.child_text("cbc:DocumentCurrencyCode"), Some("EUR"));
        assert_eq!(root.children_named("cac:InvoiceLine").count(), 1);
        assert!(root.child("cbc:ProfileID").is_none());
        assert!(!first.contains("UBLExtensions"));
    }

    #[test]
    fn a_profile_adds_bt_23_and_extension_content() {
        struct Probe;
        impl CountryProfile for Probe {
            fn id(&self) -> &'static str {
                "probe"
            }
            fn description(&self) -> &'static str {
                "probe"
            }
            fn profile_id(&self) -> Option<&'static str> {
                Some("urn:example:probe")
            }
            fn extension(&self, _invoice: &Invoice) -> Option<crate::profiles::Extension> {
                Some(
                    crate::profiles::Extension::new("probe", "urn:example:probe:1", "Stamp")
                        .with_child("probe:ID", "P-1"),
                )
            }
        }
        let document = serialize_with(&sample(), &Probe).expect("serialized");
        let root = xml::parse(&document).expect("well formed");
        assert_eq!(root.child_text("cbc:ProfileID"), Some("urn:example:probe"));
        assert_eq!(root.attribute("xmlns:probe"), Some("urn:example:probe:1"));
        let extensions = root.child("ext:UBLExtensions").expect("extensions");
        let content = extensions
            .child("ext:UBLExtension")
            .and_then(|node| node.child("ext:ExtensionContent"))
            .expect("content");
        assert_eq!(
            content
                .child("probe:Stamp")
                .and_then(|node| node.child_text("probe:ID")),
            Some("P-1")
        );
        assert_eq!(root.child_text("cbc:ID"), Some("INV-7"));
    }

    #[test]
    fn a_credit_note_uses_the_credit_note_root_and_quantity() {
        let mut invoice = sample();
        invoice.document_type = DocumentType::CreditNote;
        invoice.preceding_invoices = vec!["INV-7".to_string()];
        let xml = serialize(&invoice);
        let root = xml::parse(&xml).expect("well formed");
        assert_eq!(root.name, "CreditNote");
        assert_eq!(root.attribute("xmlns"), Some(CREDIT_NOTE_NAMESPACE));
        assert_eq!(root.child_text("cbc:CreditNoteTypeCode"), Some("381"));
        assert!(xml.contains("<cbc:CreditedQuantity"));
        assert!(!xml.contains("InvoicedQuantity"));
    }
}
