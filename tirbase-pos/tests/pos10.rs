// SPDX-License-Identifier: AGPL-3.0-only

//! POS-10 behavioural tests: tax reference cases for several jurisdictions,
//! localization, legal receipt fields, reprint marking, delivery hooks and
//! append-only invoice numbering.

use tirbase_pos::{
    CatalogItem, CatalogItemId, Currency, CurrencyPlacement, DateOrder, EmailAddress, Grouping,
    InvoiceGapPolicy, InvoiceNumber, InvoiceRegister, InvoiceSeries, Locale, LocalizationError,
    Merchant, Money, Rate, ReceiptCopy, ReceiptDocument, ReceiptError, ReceiptItemLine,
    ReceiptLabel, ReceiptLabels, ReceiptOutput, ReceiptPayment, ReceiptTotals, RenderedReceipt,
    RoundingMode, TaxApplicability, TaxBreakdown, TaxClassification, TaxComponent, TaxEngine,
    TaxError, TaxPricing, TaxProfile, TaxTreatment, TimeStyle, Timestamp,
};

fn currency(code: &str) -> Currency {
    Currency::from_code(code).unwrap()
}

fn money(code: &str, minor: i64) -> Money {
    Money::new(currency(code), minor)
}

fn rate(ppm: i32) -> Rate {
    Rate::from_ppm(ppm).unwrap()
}

fn engine(
    pricing: TaxPricing,
    rounding: RoundingMode,
    components: &[(&str, i32, bool)],
) -> TaxEngine {
    let components = components
        .iter()
        .map(|(id, percent, compounding)| {
            TaxComponent::new(*id, rate(*percent), *compounding).unwrap()
        })
        .collect();
    TaxEngine::new(pricing, rounding, components).unwrap()
}

fn ts(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn series() -> InvoiceSeries {
    InvoiceSeries::new("TILL1").unwrap()
}

fn en_us() -> Locale {
    Locale::new(
        "en-US",
        ReceiptLabels::english()
            .with(ReceiptLabel::TaxId, "Tax ID")
            .unwrap(),
    )
    .unwrap()
    .with_number_format('.', ',', Grouping::Thousands)
    .unwrap()
    .with_currency_format(CurrencyPlacement::After, true)
    .with_date_format(DateOrder::MonthDayYear, '/', TimeStyle::H12)
    .unwrap()
    .with_utc_offset_minutes(-5 * 60)
    .unwrap()
}

fn de_de() -> Locale {
    Locale::new("de-DE", ReceiptLabels::german())
        .unwrap()
        .with_number_format(',', '.', Grouping::Thousands)
        .unwrap()
        .with_currency_format(CurrencyPlacement::Before, true)
        .with_date_format(DateOrder::DayMonthYear, '.', TimeStyle::H24)
        .unwrap()
        .with_utc_offset_minutes(60)
        .unwrap()
}

#[test]
fn golden_us_ca_exclusive_sales_tax() {
    let tax = engine(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        &[("CA", 82_500, false)],
    )
    .calculate(money("USD", 10_000), TaxTreatment::Standard)
    .unwrap();
    assert_eq!(tax.net, money("USD", 10_000));
    assert_eq!(tax.tax, money("USD", 825));
    assert_eq!(tax.gross, money("USD", 10_825));
    assert_eq!(tax.rounding_adjustment, money("USD", 0));
}

#[test]
fn golden_gb_vat_inclusive() {
    let tax = engine(
        TaxPricing::Inclusive,
        RoundingMode::HalfAwayFromZero,
        &[("VAT", 200_000, false)],
    )
    .calculate(money("GBP", 12_000), TaxTreatment::Standard)
    .unwrap();
    assert_eq!(tax.net, money("GBP", 10_000));
    assert_eq!(tax.tax, money("GBP", 2_000));
    assert_eq!(tax.gross, money("GBP", 12_000));
}

#[test]
fn golden_quebec_compound_gst_qst() {
    let engine = engine(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        &[("GST", 50_000, false), ("QST", 99_750, true)],
    );
    let tax = engine
        .calculate(money("CAD", 10_000), TaxTreatment::Standard)
        .unwrap();
    assert_eq!(tax.net, money("CAD", 10_000));
    assert_eq!(tax.tax, money("CAD", 1_547));
    assert_eq!(tax.gross, money("CAD", 11_547));
    assert_eq!(tax.components[0].tax, money("CAD", 500));
    assert_eq!(tax.components[1].taxable_base, money("CAD", 10_500));
    assert_eq!(tax.components[1].tax, money("CAD", 1_047));
}

#[test]
fn golden_australia_gst_inclusive_and_rounding_residual() {
    let australia = engine(
        TaxPricing::Inclusive,
        RoundingMode::HalfAwayFromZero,
        &[("GST", 100_000, false)],
    );
    let tax = australia
        .calculate(money("AUD", 11_000), TaxTreatment::Standard)
        .unwrap();
    assert_eq!(tax.net, money("AUD", 10_000));
    assert_eq!(tax.tax, money("AUD", 1_000));
    assert_eq!(tax.gross, money("AUD", 11_000));

    // 19.95 / 1.19 extracts to 16.76; forward tax rounds to 3.18 and leaves a
    // one-cent residual that must be applied so net + tax is exactly gross.
    let germany = engine(
        TaxPricing::Inclusive,
        RoundingMode::HalfAwayFromZero,
        &[("VAT", 190_000, false)],
    );
    let tax = germany
        .calculate(money("EUR", 1_995), TaxTreatment::Standard)
        .unwrap();
    assert_eq!(tax.net, money("EUR", 1_676));
    assert_eq!(tax.tax, money("EUR", 319));
    assert_eq!(tax.gross, money("EUR", 1_995));
    assert_eq!(tax.rounding_adjustment, money("EUR", 1));
    assert_eq!(tax.components[0].tax, money("EUR", 319));
}

#[test]
fn zero_rated_and_exempt_keep_breakdown_and_collect_nothing() {
    for treatment in [TaxTreatment::ZeroRated, TaxTreatment::Exempt] {
        for pricing in [TaxPricing::Exclusive, TaxPricing::Inclusive] {
            let engine = engine(
                pricing,
                RoundingMode::HalfAwayFromZero,
                &[("VAT", 200_000, false)],
            );
            let tax = engine.calculate(money("EUR", 5_000), treatment).unwrap();
            assert_eq!(tax.treatment, treatment);
            assert_eq!(tax.net, money("EUR", 5_000));
            assert_eq!(tax.tax, money("EUR", 0));
            assert_eq!(tax.gross, money("EUR", 5_000));
            assert_eq!(tax.components.len(), 1);
            assert!(tax.components[0].tax.is_zero());
        }
    }
}

#[test]
fn compound_components_must_precede_simple_ones() {
    let result = TaxEngine::new(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        vec![
            TaxComponent::new("QST", rate(99_750), true).unwrap(),
            TaxComponent::new("GST", rate(50_000), false).unwrap(),
        ],
    );
    assert_eq!(
        result,
        Err(TaxError::NonCompoundingAfterCompound("GST".into()))
    );
    assert_eq!(
        TaxError::NonCompoundingAfterCompound("GST".into()).code(),
        "tax.compound_order"
    );
}

#[test]
fn profile_applies_item_category_then_all_precedence() {
    let item = CatalogItem::new(CatalogItemId::new("coffee").unwrap(), "Coffee")
        .unwrap()
        .with_category("drinks")
        .unwrap();
    let other = CatalogItem::new(CatalogItemId::new("bag").unwrap(), "Bag").unwrap();
    let engine = engine(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        &[("VAT", 200_000, false)],
    );
    let profile = TaxProfile::new(
        tirbase_pos::JurisdictionId::new("GB").unwrap(),
        currency("GBP"),
        engine,
        vec![
            TaxClassification::new(TaxApplicability::All, TaxTreatment::Standard).unwrap(),
            TaxClassification::new(
                TaxApplicability::Category("drinks".into()),
                TaxTreatment::Exempt,
            )
            .unwrap(),
            TaxClassification::new(
                TaxApplicability::Item(item.id().clone()),
                TaxTreatment::ZeroRated,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(profile.treatment_for(&item), TaxTreatment::ZeroRated);
    assert_eq!(profile.treatment_for(&other), TaxTreatment::Standard);
    let tax = profile
        .calculate_for_item(money("GBP", 500), &item)
        .unwrap();
    assert!(tax.tax.is_zero());
}

#[test]
fn localization_formats_money_dates_numbers_and_language() {
    let us = en_us();
    assert_eq!(us.format_money(money("USD", 123_456)), "1,234.56 USD");
    assert_eq!(us.format_money(money("USD", -123_456)), "-1,234.56 USD");
    assert_eq!(us.format_number(1_234_567), "1,234,567");
    assert_eq!(us.format_quantity(1_500), "1.5");
    assert_eq!(us.format_rate(rate(99_750)), "9.975%");
    assert_eq!(us.format_datetime(ts(0)).unwrap(), "12/31/1969 7:00 PM");

    let de = de_de();
    assert_eq!(de.format_money(money("EUR", 123_456)), "EUR 1.234,56");
    assert_eq!(de.format_rate(rate(190_000)), "19%");
    assert_eq!(de.format_datetime(ts(0)).unwrap(), "01.01.1970 01:00");
    assert_eq!(de.label(ReceiptLabel::Subtotal), "Zwischensumme");
    assert_eq!(de.label(ReceiptLabel::Reprint), "NACHDRUCK");
}

#[test]
fn localization_rejects_ambiguous_or_unsafe_configuration() {
    assert_eq!(
        Locale::new("", ReceiptLabels::english()),
        Err(LocalizationError::EmptyLanguage)
    );
    assert_eq!(
        Locale::new("en US", ReceiptLabels::english()),
        Err(LocalizationError::InvalidLanguage)
    );
    let locale = en_us();
    assert_eq!(
        locale
            .clone()
            .with_number_format('.', '.', Grouping::Thousands),
        Err(LocalizationError::SeparatorsEqual)
    );
    assert_eq!(
        locale.with_utc_offset_minutes(15 * 60),
        Err(LocalizationError::InvalidUtcOffset)
    );
    assert_eq!(
        ReceiptLabels::english().with(ReceiptLabel::Total, ""),
        Err(LocalizationError::InvalidLabel(ReceiptLabel::Total))
    );
}

#[derive(Default)]
struct RecordingOutput {
    printed: Vec<InvoiceNumber>,
    emailed: Vec<(InvoiceNumber, EmailAddress)>,
    reprints: Vec<bool>,
}

impl ReceiptOutput for RecordingOutput {
    fn print(&mut self, receipt: &RenderedReceipt) -> Result<(), ReceiptError> {
        self.printed.push(receipt.invoice().clone());
        self.reprints.push(receipt.is_reprint());
        Ok(())
    }

    fn email(&mut self, receipt: &RenderedReceipt, to: &EmailAddress) -> Result<(), ReceiptError> {
        self.emailed.push((receipt.invoice().clone(), to.clone()));
        self.reprints.push(receipt.is_reprint());
        Ok(())
    }
}

fn receipt(
    register: &mut InvoiceRegister,
    tax: &TaxEngine,
    copy: bool,
) -> (ReceiptDocument, InvoiceNumber) {
    let invoice = register.issue(ts(0)).unwrap();
    let breakdown = tax
        .calculate(money("USD", 10_000), TaxTreatment::Standard)
        .unwrap();
    let totals = ReceiptTotals::new(
        money("USD", 10_000),
        money("USD", 0),
        breakdown.tax,
        money("USD", 0),
        money("USD", 11_000),
    )
    .unwrap();
    let merchant = Merchant::new(
        "Example Coffee Ltd",
        vec!["1 Market Street".into(), "San Francisco, CA".into()],
        "US-CA-123456",
    )
    .unwrap();
    let mut document = ReceiptDocument::new(merchant, invoice.clone(), ts(0), totals, breakdown)
        .unwrap()
        .with_reference("till-1", "emp-7", "check-42")
        .unwrap()
        .with_line(
            ReceiptItemLine::new("Coffee", 1_000, money("USD", 10_000), money("USD", 10_000))
                .unwrap(),
        )
        .unwrap()
        .with_payment(ReceiptPayment::new("Cash", money("USD", 11_000)).unwrap())
        .unwrap()
        .with_footer("Thank you for your visit.")
        .unwrap();
    if copy {
        let count = register.mark_reprinted(&invoice).unwrap();
        document = document.as_reprint(count).unwrap();
    }
    (document, invoice)
}

#[test]
fn receipt_has_legal_fields_and_localized_tax_line() {
    let mut register = InvoiceRegister::new(series(), InvoiceGapPolicy::Gapless, 4, 1).unwrap();
    let tax = engine(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        &[("CA", 82_500, false)],
    );
    let (document, invoice) = receipt(&mut register, &tax, false);
    let rendered = document.render(&en_us()).unwrap();
    let text = rendered.text();
    assert_eq!(rendered.copy(), ReceiptCopy::Original);
    assert!(!rendered.is_reprint());
    assert_eq!(rendered.invoice(), &invoice);
    for expected in [
        "Example Coffee Ltd",
        "1 Market Street",
        "Tax ID: US-CA-123456",
        "Invoice: TILL1-0001",
        "Date: 12/31/1969 7:00 PM",
        "Terminal: till-1",
        "Operator: emp-7",
        "Reference: check-42",
        "1 x Coffee",
        "Tax CA 8.25%",
        "Total",
        "108.25 USD",
        "Change",
        "1.75 USD",
        "Thank you for your visit.",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
    assert_eq!(document.totals().change(), money("USD", 175));
}

#[test]
fn reprint_is_visibly_marked_and_does_not_allocate_a_number() {
    let mut register = InvoiceRegister::new(series(), InvoiceGapPolicy::Gapless, 4, 1).unwrap();
    let tax = engine(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        &[("CA", 82_500, false)],
    );
    let (document, invoice) = receipt(&mut register, &tax, true);
    let next = register.next_sequence();
    let rendered = document.render(&en_us()).unwrap();
    assert!(rendered.is_reprint());
    assert_eq!(rendered.copy(), ReceiptCopy::Reprint);
    assert_eq!(rendered.invoice(), &invoice);
    assert!(rendered.lines()[0].contains("REPRINT #1"));
    assert_eq!(register.next_sequence(), next);
    assert_eq!(register.reprint_count(&invoice), 1);
    assert!(register.was_issued(&invoice));
}

#[test]
fn print_and_email_hooks_receive_the_same_marked_document() {
    let mut register = InvoiceRegister::new(series(), InvoiceGapPolicy::Gapless, 4, 1).unwrap();
    let tax = engine(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        &[("CA", 82_500, false)],
    );
    let (document, invoice) = receipt(&mut register, &tax, true);
    let to = EmailAddress::new("guest@example.com").unwrap();
    let mut output = RecordingOutput::default();
    document.print(&en_us(), &mut output).unwrap();
    document.email(&en_us(), &to, &mut output).unwrap();
    assert_eq!(output.printed, vec![invoice.clone()]);
    assert_eq!(output.emailed, vec![(invoice, to)]);
    assert_eq!(output.reprints, vec![true, true]);
}

#[test]
fn invalid_receipt_is_rejected_before_rendering() {
    let mut register = InvoiceRegister::new(series(), InvoiceGapPolicy::Gapless, 4, 1).unwrap();
    let tax = engine(
        TaxPricing::Exclusive,
        RoundingMode::HalfAwayFromZero,
        &[("CA", 82_500, false)],
    );
    let (document, _) = receipt(&mut register, &tax, false);
    let missing_payment = ReceiptDocument::new(
        document.merchant().clone(),
        document.invoice().clone(),
        document.issued_at(),
        *document.totals(),
        document.tax().clone(),
    )
    .unwrap()
    .with_reference("till-1", "emp-7", "check-42")
    .unwrap()
    .with_line(
        ReceiptItemLine::new("Coffee", 1_000, money("USD", 10_000), money("USD", 10_000)).unwrap(),
    )
    .unwrap();
    assert_eq!(missing_payment.validate(), Err(ReceiptError::NoPayments));
    assert_eq!(
        ReceiptTotals::new(
            money("USD", 1_000),
            money("USD", 1_001),
            money("USD", 0),
            money("USD", 0),
            money("USD", 1_000),
        ),
        Err(ReceiptError::DiscountExceedsSubtotal)
    );
    assert_eq!(
        EmailAddress::new("not-an-address"),
        Err(ReceiptError::InvalidEmail)
    );
}

#[test]
fn gapless_register_refuses_to_consume_a_number() {
    let mut register = InvoiceRegister::new(series(), InvoiceGapPolicy::Gapless, 4, 1).unwrap();
    let first = register.issue(ts(0)).unwrap();
    assert_eq!(first.to_string(), "TILL1-0001");
    let next = register.next_sequence();
    assert_eq!(
        register.record_gap(ts(1), "printer offline"),
        Err(tirbase_pos::InvoiceError::GapNotAllowed)
    );
    assert_eq!(register.next_sequence(), next);
    let second = register.issue(ts(2)).unwrap();
    assert_eq!(second.to_string(), "TILL1-0002");
    assert!(register.gaps().is_empty());
}

#[test]
fn documented_gap_is_recorded_and_restored_without_reuse() {
    let mut register = InvoiceRegister::new(series(), InvoiceGapPolicy::Documented, 4, 1).unwrap();
    let first = register.issue(ts(0)).unwrap();
    let gap = register.record_gap(ts(1), "printer offline").unwrap();
    let third = register.issue(ts(2)).unwrap();
    assert_eq!(first.to_string(), "TILL1-0001");
    assert_eq!(gap.number().to_string(), "TILL1-0002");
    assert_eq!(gap.reason(), "printer offline");
    assert_eq!(third.to_string(), "TILL1-0003");
    assert_eq!(register.next_sequence(), 4);

    let restored = InvoiceRegister::from_ledger(
        series(),
        InvoiceGapPolicy::Documented,
        4,
        1,
        register.issued().to_vec(),
        register.gaps().to_vec(),
    )
    .unwrap();
    assert_eq!(restored.next_sequence(), 4);
    assert_eq!(restored.issued().len(), 2);
    assert_eq!(restored.gaps().len(), 1);

    let duplicate = InvoiceRegister::from_ledger(
        series(),
        InvoiceGapPolicy::Documented,
        4,
        1,
        vec![restored.issued()[0].clone(), restored.issued()[0].clone()],
        Vec::new(),
    );
    assert!(matches!(
        duplicate,
        Err(tirbase_pos::InvoiceError::DuplicateNumber(_))
    ));

    let missing_gap = InvoiceRegister::from_ledger(
        series(),
        InvoiceGapPolicy::Documented,
        4,
        1,
        restored.issued().to_vec(),
        Vec::new(),
    );
    assert_eq!(
        missing_gap,
        Err(tirbase_pos::InvoiceError::UndocumentedGap(2))
    );
}

#[test]
fn reprint_uses_existing_number_and_next_issue_remains_unique() {
    let mut register = InvoiceRegister::new(series(), InvoiceGapPolicy::Gapless, 4, 1).unwrap();
    let first = register.issue(ts(0)).unwrap();
    assert_eq!(register.mark_reprinted(&first).unwrap(), 1);
    assert_eq!(register.mark_reprinted(&first).unwrap(), 2);
    let second = register.issue(ts(1)).unwrap();
    assert_ne!(first, second);
    assert_eq!(register.reprint_count(&first), 2);
    assert_eq!(register.next_sequence(), 3);
    let unknown = second.clone();
    let mut other = InvoiceRegister::new(
        InvoiceSeries::new("TILL2").unwrap(),
        InvoiceGapPolicy::Gapless,
        4,
        1,
    )
    .unwrap();
    assert!(matches!(
        other.mark_reprinted(&unknown),
        Err(tirbase_pos::InvoiceError::UnknownInvoice(_))
    ));
}

#[test]
fn tax_breakdown_is_a_value_the_receipt_can_compare() {
    let tax: TaxBreakdown = engine(
        TaxPricing::Inclusive,
        RoundingMode::HalfAwayFromZero,
        &[("VAT", 200_000, false)],
    )
    .calculate(money("GBP", 1_200), TaxTreatment::Standard)
    .unwrap();
    assert_eq!(tax.net.checked_add(tax.tax).unwrap(), tax.gross);
}
