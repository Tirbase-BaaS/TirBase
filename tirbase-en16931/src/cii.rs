// SPDX-License-Identifier: Apache-2.0

//! UN/CEFACT CII D16B serialization.
//!
//! The document is an `rsm:CrossIndustryInvoice` with the `ram:` reusable
//! aggregate and `udt:` unqualified datatype namespaces, in the element order the
//! CII D16B schema sequence requires. Amounts have two decimals, quantities carry
//! a UN/ECE Recommendation 20 `unitCode`, and dates use the `format="102"`
//! `YYYYMMDD` form.

use crate::model::{
    format_money, format_percent, format_quantity, AllowanceCharge, Invoice, Party,
};
use crate::profiles::CountryProfile;
use crate::xml::Writer;

/// CII root namespace.
pub const CII_NAMESPACE: &str = "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100";

/// CII reusable aggregate business information entity namespace.
pub const RAM_NAMESPACE: &str =
    "urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100";

/// CII unqualified datatype namespace.
pub const UDT_NAMESPACE: &str = "urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100";

/// Serialize an invoice as CII D16B.
pub fn serialize(invoice: &Invoice) -> String {
    build(invoice, crate::SPECIFICATION_ID)
}

/// Serialize as CII D16B under a country profile.
///
/// The profile supplies the specification identifier (BT-24 in CII, the guideline
/// context parameter) and the last pass over the finished document, which is where
/// national content belongs; a refusal from the profile is returned, never papered
/// over.
pub fn serialize_with(invoice: &Invoice, profile: &dyn CountryProfile) -> Result<String, String> {
    let document = build(invoice, profile.customization_id());
    profile.wrap(crate::validate::Syntax::Cii, document)
}

fn build(invoice: &Invoice, customization_id: &str) -> String {
    let mut writer = Writer::new();
    writer.open(
        "rsm:CrossIndustryInvoice",
        &[
            ("xmlns:rsm", CII_NAMESPACE),
            ("xmlns:ram", RAM_NAMESPACE),
            ("xmlns:udt", UDT_NAMESPACE),
        ],
    );

    writer.open("rsm:ExchangedDocumentContext", &[]);
    writer.open("ram:GuidelineSpecifiedDocumentContextParameter", &[]);
    writer.element("ram:ID", &[], customization_id);
    writer.close("ram:GuidelineSpecifiedDocumentContextParameter");
    writer.close("rsm:ExchangedDocumentContext");

    writer.open("rsm:ExchangedDocument", &[]);
    writer.element("ram:ID", &[], &invoice.number);
    writer.element("ram:TypeCode", &[], invoice.document_type.code());
    writer.open("ram:IssueDateTime", &[]);
    writer.element(
        "udt:DateTimeString",
        &[("format", "102")],
        &invoice.issue_date.to_compact(),
    );
    writer.close("ram:IssueDateTime");
    if let Some(note) = &invoice.note {
        writer.open("ram:IncludedNote", &[]);
        writer.element("ram:Content", &[], note);
        writer.close("ram:IncludedNote");
    }
    writer.close("rsm:ExchangedDocument");

    writer.open("rsm:SupplyChainTradeTransaction", &[]);
    for line in &invoice.lines {
        writer.open("ram:IncludedSupplyChainTradeLineItem", &[]);
        writer.open("ram:AssociatedDocumentLineDocument", &[]);
        writer.element("ram:LineID", &[], &line.id);
        writer.close("ram:AssociatedDocumentLineDocument");
        writer.open("ram:SpecifiedTradeProduct", &[]);
        writer.element("ram:Name", &[], &line.name);
        if let Some(description) = &line.description {
            writer.element("ram:Description", &[], description);
        }
        writer.close("ram:SpecifiedTradeProduct");
        writer.open("ram:SpecifiedLineTradeAgreement", &[]);
        writer.open("ram:NetPriceProductTradePrice", &[]);
        writer.element(
            "ram:ChargeAmount",
            &[],
            &format_money(line.unit_price_minor),
        );
        writer.close("ram:NetPriceProductTradePrice");
        writer.close("ram:SpecifiedLineTradeAgreement");
        writer.open("ram:SpecifiedLineTradeDelivery", &[]);
        writer.element(
            "ram:BilledQuantity",
            &[("unitCode", &line.unit_code)],
            &format_quantity(line.quantity_milli),
        );
        writer.close("ram:SpecifiedLineTradeDelivery");
        writer.open("ram:SpecifiedLineTradeSettlement", &[]);
        writer.open("ram:ApplicableTradeTax", &[]);
        writer.element("ram:TypeCode", &[], "VAT");
        writer.element("ram:CategoryCode", &[], line.vat_category.code());
        writer.element(
            "ram:RateApplicablePercent",
            &[],
            &format_percent(line.vat_rate_bp),
        );
        writer.close("ram:ApplicableTradeTax");
        if line.allowance_minor > 0 {
            let allowance = AllowanceCharge {
                reason: line
                    .allowance_reason
                    .clone()
                    .unwrap_or_else(|| "Line discount".to_string()),
                amount_minor: line.allowance_minor,
                percent_bp: None,
                base_minor: None,
                vat_category: line.vat_category,
                vat_rate_bp: line.vat_rate_bp,
            };
            allowance_charge(&mut writer, &allowance, false);
        }
        writer.open("ram:SpecifiedTradeSettlementLineMonetarySummation", &[]);
        writer.element("ram:LineTotalAmount", &[], &format_money(line.net_minor()));
        writer.close("ram:SpecifiedTradeSettlementLineMonetarySummation");
        writer.close("ram:SpecifiedLineTradeSettlement");
        writer.close("ram:IncludedSupplyChainTradeLineItem");
    }

    writer.open("ram:ApplicableHeaderTradeAgreement", &[]);
    if let Some(reference) = &invoice.buyer_reference {
        writer.element("ram:BuyerReference", &[], reference);
    }
    writer.open("ram:SellerTradeParty", &[]);
    party(&mut writer, &invoice.seller);
    writer.close("ram:SellerTradeParty");
    writer.open("ram:BuyerTradeParty", &[]);
    party(&mut writer, &invoice.buyer);
    writer.close("ram:BuyerTradeParty");
    writer.close("ram:ApplicableHeaderTradeAgreement");

    writer.empty("ram:ApplicableHeaderTradeDelivery", &[]);

    writer.open("ram:ApplicableHeaderTradeSettlement", &[]);
    if let Some(reference) = &invoice.payment_reference {
        writer.element("ram:PaymentReference", &[], reference);
    }
    writer.element("ram:InvoiceCurrencyCode", &[], &invoice.currency);
    if let Some(means) = &invoice.payment_means {
        writer.open("ram:SpecifiedTradeSettlementPaymentMeans", &[]);
        writer.element("ram:TypeCode", &[], &means.code);
        if let Some(instruction) = &means.instruction {
            writer.element("ram:Information", &[], instruction);
        }
        writer.close("ram:SpecifiedTradeSettlementPaymentMeans");
    }
    let totals = invoice.totals();
    for group in &totals.breakdown {
        writer.open("ram:ApplicableTradeTax", &[]);
        writer.element("ram:CalculatedAmount", &[], &format_money(group.tax_minor));
        writer.element("ram:TypeCode", &[], "VAT");
        writer.element("ram:BasisAmount", &[], &format_money(group.taxable_minor));
        writer.element("ram:CategoryCode", &[], group.vat_category.code());
        writer.element(
            "ram:RateApplicablePercent",
            &[],
            &format_percent(group.vat_rate_bp),
        );
        writer.close("ram:ApplicableTradeTax");
    }
    for entry in &invoice.allowances {
        allowance_charge(&mut writer, entry, false);
    }
    for entry in &invoice.charges {
        allowance_charge(&mut writer, entry, true);
    }
    if invoice.due_date.is_some() {
        writer.open("ram:SpecifiedTradePaymentTerms", &[]);
        if let Some(due) = invoice.due_date {
            writer.open("ram:DueDateDateTime", &[]);
            writer.element(
                "udt:DateTimeString",
                &[("format", "102")],
                &due.to_compact(),
            );
            writer.close("ram:DueDateDateTime");
        }
        writer.close("ram:SpecifiedTradePaymentTerms");
    }
    writer.open("ram:SpecifiedTradeSettlementHeaderMonetarySummation", &[]);
    writer.element(
        "ram:LineTotalAmount",
        &[],
        &format_money(totals.line_total_minor),
    );
    if totals.charge_total_minor > 0 {
        writer.element(
            "ram:ChargeTotalAmount",
            &[],
            &format_money(totals.charge_total_minor),
        );
    }
    if totals.allowance_total_minor > 0 {
        writer.element(
            "ram:AllowanceTotalAmount",
            &[],
            &format_money(totals.allowance_total_minor),
        );
    }
    writer.element(
        "ram:TaxBasisTotalAmount",
        &[],
        &format_money(totals.tax_exclusive_minor),
    );
    writer.element(
        "ram:TaxTotalAmount",
        &[("currencyID", &invoice.currency)],
        &format_money(totals.tax_total_minor),
    );
    if totals.rounding_minor != 0 {
        writer.element(
            "ram:RoundingAmount",
            &[],
            &format_money(totals.rounding_minor),
        );
    }
    writer.element(
        "ram:GrandTotalAmount",
        &[],
        &format_money(totals.tax_inclusive_minor),
    );
    if totals.prepaid_minor > 0 {
        writer.element(
            "ram:TotalPrepaidAmount",
            &[],
            &format_money(totals.prepaid_minor),
        );
    }
    writer.element(
        "ram:DuePayableAmount",
        &[],
        &format_money(totals.payable_minor),
    );
    writer.close("ram:SpecifiedTradeSettlementHeaderMonetarySummation");
    for reference in &invoice.preceding_invoices {
        writer.open("ram:InvoiceReferencedDocument", &[]);
        writer.element("ram:IssuerAssignedID", &[], reference);
        writer.close("ram:InvoiceReferencedDocument");
    }
    writer.close("ram:ApplicableHeaderTradeSettlement");
    writer.close("rsm:SupplyChainTradeTransaction");
    writer.close("rsm:CrossIndustryInvoice");
    writer.finish()
}

fn party(writer: &mut Writer, party: &Party) {
    if let Some((id, scheme)) = &party.legal_id {
        writer.open("ram:SpecifiedLegalOrganization", &[]);
        writer.element("ram:ID", &[("schemeID", scheme)], id);
        writer.close("ram:SpecifiedLegalOrganization");
    }
    writer.element("ram:Name", &[], &party.name);
    writer.open("ram:PostalTradeAddress", &[]);
    writer.element("ram:PostcodeCode", &[], &party.address.postcode);
    writer.element("ram:LineOne", &[], &party.address.line1);
    if let Some(line2) = &party.address.line2 {
        writer.element("ram:LineTwo", &[], line2);
    }
    writer.element("ram:CityName", &[], &party.address.city);
    writer.element("ram:CountryID", &[], &party.address.country);
    writer.close("ram:PostalTradeAddress");
    if let Some((endpoint, scheme)) = &party.endpoint {
        writer.open("ram:URIUniversalCommunication", &[]);
        writer.element("ram:URIID", &[("schemeID", scheme)], endpoint);
        writer.close("ram:URIUniversalCommunication");
    }
    if let Some(vat_id) = &party.vat_id {
        writer.open("ram:SpecifiedTaxRegistration", &[]);
        writer.element("ram:ID", &[("schemeID", "VA")], vat_id);
        writer.close("ram:SpecifiedTaxRegistration");
    }
}

fn allowance_charge(writer: &mut Writer, entry: &AllowanceCharge, is_charge: bool) {
    writer.open("ram:SpecifiedTradeAllowanceCharge", &[]);
    writer.open("ram:ChargeIndicator", &[]);
    writer.element(
        "udt:Indicator",
        &[],
        if is_charge { "true" } else { "false" },
    );
    writer.close("ram:ChargeIndicator");
    writer.element("ram:ActualAmount", &[], &format_money(entry.amount_minor));
    writer.element("ram:Reason", &[], &entry.reason);
    writer.open("ram:CategoryTradeTax", &[]);
    writer.element("ram:TypeCode", &[], "VAT");
    writer.element("ram:CategoryCode", &[], entry.vat_category.code());
    writer.element(
        "ram:RateApplicablePercent",
        &[],
        &format_percent(entry.vat_rate_bp),
    );
    writer.close("ram:CategoryTradeTax");
    writer.close("ram:SpecifiedTradeAllowanceCharge");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Address, Date, DocumentType, Invoice, InvoiceLine, Party, VatCategory};
    use crate::xml;

    fn sample() -> Invoice {
        Invoice {
            number: "INV-8".to_string(),
            issue_date: Date::new(2026, 4, 2).expect("date"),
            due_date: Some(Date::new(2026, 5, 2).expect("date")),
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
        assert_eq!(first, serialize(&invoice));
        let root = xml::parse(&first).expect("well formed");
        assert_eq!(root.name, "rsm:CrossIndustryInvoice");
        assert_eq!(root.attribute("xmlns:ram"), Some(RAM_NAMESPACE));
        let document = root.child("rsm:ExchangedDocument").expect("document");
        assert_eq!(document.child_text("ram:ID"), Some("INV-8"));
        assert_eq!(document.child_text("ram:TypeCode"), Some("380"));
        assert_eq!(
            document
                .child("ram:IssueDateTime")
                .and_then(|node| node.child("udt:DateTimeString"))
                .and_then(|node| node.attribute("format")),
            Some("102")
        );
        assert_eq!(
            root.child("rsm:ExchangedDocumentContext")
                .and_then(|node| node.child("ram:GuidelineSpecifiedDocumentContextParameter"))
                .and_then(|node| node.child_text("ram:ID")),
            Some(crate::SPECIFICATION_ID)
        );
    }

    #[test]
    fn a_profile_supplies_the_specification_identifier() {
        struct Probe;
        impl CountryProfile for Probe {
            fn id(&self) -> &'static str {
                "probe"
            }
            fn description(&self) -> &'static str {
                "probe"
            }
            fn customization_id(&self) -> &'static str {
                "urn:example:probe:v1"
            }
        }
        let document = serialize_with(&sample(), &Probe).expect("serialized");
        assert!(document.contains("urn:example:probe:v1"));
        assert!(!document.contains(crate::SPECIFICATION_ID));
    }
}
