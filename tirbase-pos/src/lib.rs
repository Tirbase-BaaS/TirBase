// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-pos — POS order, check, line-item and money model
//!
//! **Prototype status.** This crate is POS-01 through POS-12 domain-model and
//! device-codec engineering under the deferral recorded in
//! [`POS-00`](../docs/compliance/pos-00-partner-compliance-gate.md). It is not a
//! production POS, is not certified, moves no money, and must not be presented
//! as any of those things. It contains no card-data field, no processor
//! integration, no fiscal module and no jurisdiction default.
//!
//! ## What is modelled
//!
//! - **Ownership** ([`ownership`]) — store, terminal, employee and optional
//!   customer, validated as one consistent scope.
//! - **Order** ([`order`]) — the aggregate root, idempotent command stream and
//!   append-only audit log.
//! - **Check and state machine** ([`check`]) — `Open → Held → Closed →
//!   Refunded`, plus `Voided` and the terminal merge state `Merged`; content is
//!   mutable only while open or held.
//! - **Replicated operation book** ([`book`]) — split check, split line,
//!   transfer item/check, void line/payment and merge checks, with idempotent
//!   replay and a canonical rebuild order for deterministic offline conflicts.
//! - **Payment intents** ([`intent`]) — an idempotent `Created → Authorized →
//!   Captured → Refunded`/`Voided` ledger. The idempotency key is bound to the
//!   check, amount, currency, terminal and operator; duplicate requests return
//!   the original result, and amount/currency mismatches are rejected. Only an
//!   opaque processor token is stored (no PAN/CVV), and a journal plus
//!   processor-report reconciliation covers crash recovery.
//! - **Catalog, price book and tax versions** ([`catalog`]) — immutable
//!   versions with half-open effective windows. Overlapping windows in the
//!   same scope are rejected; orders pin the exact catalog, price-book and
//!   tax-table versions they used; a rollback reissues old content under a new
//!   version and records an audit event. Pricing resolves item, modifier and
//!   tax values into an ordinary POS-01 [`LineItem`], so a closed check keeps
//!   its original money.
//! - **Refund, discount and void guard** ([`guard`]) — refund caps by operator,
//!   terminal, UTC day and check; line/check percentage and absolute discount
//!   caps with stacking rules; M-of-N approvals bound to action, check, amount,
//!   currency, reason and expiry; no self-approval and single-use consumption.
//!   Every denial appends a security event with a stable [`DenialCode`].
//! - **ESC/POS receipt and cash drawer** ([`escpos`], [`printer`]) — a pure,
//!   fixed-capacity ESC/POS codec for text, alignment, emphasis, feed, cut,
//!   CODE128/EAN-13 barcodes, QR symbols, code pages, drawer pulses and status
//!   queries. [`ReceiptPrinter`] owns the transport: it validates the receipt,
//!   checks printer status into a fixed-size buffer, encodes the whole job and
//!   only then writes it, pulsing the drawer exactly once for a cash sale.
//!   Device status bytes are decoded without panicking, and
//!   [`SimulatedPrinter`] records print/drawer flows for tests and HIL
//!   rehearsals.
//! - **Scale, scanner and kitchen display** ([`scale`], [`scanner`], [`kds`]) —
//!   two bounded serial scale protocols with stable-weight detection, tare,
//!   units and overflow/underload faults; keyboard-wedge and serial barcode
//!   framing with GS1 application identifiers; and a ticket/line/status KDS
//!   codec with idempotent ticket IDs, delivery acknowledgements and retry.
//!   Each endpoint owns its transport, and [`SimulatedScale`],
//!   [`SimulatedScanner`] and [`SimulatedKds`] record device flows.
//! - **Payment envelope and anti-replay** ([`envelope`]) — every capture,
//!   refund and void executed by [`PaymentDesk`] is checked against the check
//!   total, tip, amount, currency, terminal, operator and terminal epoch. A
//!   terminal-supplied nonce plus monotonic counter rejects cross-terminal and
//!   cross-epoch reuse, an identical repeat inside the bounded window returns
//!   the original intent without executing twice, and a supplied approval is
//!   bound to the exact payment.
//! - **Tax and localization** ([`tax`], [`localization`]) — ordered,
//!   inclusive/exclusive, compounding tax components with explicit rounding;
//!   zero-rated and exempt treatments; product/category applicability; and
//!   integer-only formatting of money, rates, quantities, dates and receipt
//!   labels. No jurisdiction default or legal rate is built in.
//! - **Receipts and invoice numbering** ([`receipt`], [`numbering`]) — a
//!   validated receipt document with seller, tax and operator legal fields,
//!   localized rendering, an unmissable reprint copy marker, print/email hooks,
//!   and an append-only invoice ledger that never silently reuses a number and
//!   supports gapless or explicitly documented gap policies.
//! - **Employees, shifts and cash** ([`staff`], [`shift`]) — an employee
//!   directory with role-derived operational permissions and opaque PIN/badge
//!   references, plus per-terminal shifts with an opening float, cash in/out,
//!   safe drops, operator-attributed drawer-count variance, read-only X
//!   reports, a closing Z report that seals the shift, and idempotent offline
//!   reconciliation that cannot duplicate a cash movement.
//! - **Settlement, chargebacks and tips** ([`settlement`], [`tip`]) — settlement
//!   batches per processor, terminal and day, built from validated processor
//!   files; reconciliation that leaves every captured intent either matched or
//!   in an exception queue whose keys are deterministic, so a re-run neither
//!   duplicates nor silently drops a problem; a chargeback lifecycle with
//!   evidence links that pays a lost case exactly once; and tip adjustment,
//!   pooling and payout whose allocations always add up to the pooled tips.
//! - **Line items** ([`line_item`]) — quantity, unit price, modifiers, discount
//!   and tax rate, with exact per-line arithmetic.
//! - **Money** ([`money`]) — integer ISO 4217 minor units; no floats.
//!
//! ## Exactness
//!
//! All money is an `i64` count of minor units. The only rounding points are
//! `quantity × unit price`, a percentage discount, and a tax rate. Each uses
//! the check's fixed [`RoundingMode`] over `i128` intermediates. Check totals are
//! exact sums of per-line values:
//!
//! ```text
//! subtotal       = Σ line base
//! discount_total = Σ line discount
//! tax_total      = Σ line tax = Σ tax-line tax
//! grand_total    = subtotal − discount_total + tax_total + tip
//! amount_due     = grand_total − (paid_total − refunded_total)
//! ```
//!
//! Closing freezes the line-derived totals, and a closed check rejects every
//! content mutation with [`PosError::CheckNotMutable`].
//!
//! ## Offline convergence
//!
//! [`PosBook`] stores the operations it has applied and rebuilds all orders
//! deterministically in `(lamport, actor terminal, operation id)` order. A
//! merge unions two operation logs and rebuilds, so replicas that saw the same
//! operations converge regardless of merge direction. Replaying an operation
//! returns [`ApplyOutcome::Replayed`] without applying it twice. A conflict
//! that canonical order cannot resolve (for example a merge with duplicate
//! identifiers, a different currency, or two operations voiding the same
//! target) is rejected with a stable [`PosError`] and stored in
//! [`PosBook::rejected_operations`]. Splits and merges preserve tax, discount,
//! tip and payment allocation exactly, or fail explicitly instead of losing
//! money.
//!
//! ## Example
//!
//! ```
//! use tirbase_pos::{
//!     CheckId, CheckStatus, Currency, Employee, EmployeeId, EmployeeRole, LineItem,
//!     LineItemId, Money, OperationId, Order, OrderCommand, Organization, Ownership,
//!     PaymentId, PaymentLink, PaymentMethod, Quantity, Rate, RoundingMode, Store,
//!     StoreId, Terminal, TerminalId, Timestamp,
//! };
//!
//! # fn main() -> Result<(), tirbase_pos::PosError> {
//! let store_id = StoreId::new("store-1")?;
//! let mut org = Organization::new();
//! org.add_store(Store::new(store_id.clone(), "Store One")?)?;
//! org.add_terminal(Terminal::new(
//!     TerminalId::new("till-1")?,
//!     store_id.clone(),
//!     "Till 1",
//! )?)?;
//! org.add_employee(Employee::new(
//!     EmployeeId::new("emp-1")?,
//!     store_id.clone(),
//!     "Ada",
//!     vec![EmployeeRole::Cashier],
//! )?)?;
//! let ownership = Ownership::new(
//!     store_id,
//!     TerminalId::new("till-1")?,
//!     EmployeeId::new("emp-1")?,
//!     None,
//! );
//!
//! let mut order = Order::open(
//!     tirbase_pos::OrderId::new("order-1")?,
//!     ownership,
//!     &org,
//!     Timestamp::from_millis(1_000),
//! )?;
//! let check_id = CheckId::new("check-1")?;
//! let usd = Currency::from_code("USD")?;
//! order.apply(OrderCommand::CreateCheck {
//!     operation_id: OperationId::new("op-1")?,
//!     check_id: check_id.clone(),
//!     currency: usd,
//!     rounding: RoundingMode::HalfAwayFromZero,
//!     at: Timestamp::from_millis(1_001),
//! })?;
//! order.apply(OrderCommand::AddLineItem {
//!     operation_id: OperationId::new("op-2")?,
//!     check_id: check_id.clone(),
//!     line: LineItem::new(
//!         LineItemId::new("line-1")?,
//!         "Coffee",
//!         Quantity::from_units(2)?,
//!         Money::new(usd, 450),
//!     )?
//!     .with_tax_rate(Rate::from_percent(10)?),
//!     at: Timestamp::from_millis(1_002),
//! })?;
//! order.apply(OrderCommand::SetTip {
//!     operation_id: OperationId::new("op-3")?,
//!     check_id: check_id.clone(),
//!     tip: Money::new(usd, 100),
//!     at: Timestamp::from_millis(1_003),
//! })?;
//!
//! let check = order.check(&check_id).unwrap();
//! let totals = check.totals()?;
//! assert_eq!(totals.subtotal, Money::new(usd, 900));
//! assert_eq!(totals.tax_total, Money::new(usd, 90));
//! assert_eq!(totals.grand_total, Money::new(usd, 1_090));
//!
//! order.apply(OrderCommand::LinkPayment {
//!     operation_id: OperationId::new("op-4")?,
//!     check_id: check_id.clone(),
//!     payment: PaymentLink::captured(
//!         PaymentId::new("pay-1")?,
//!         PaymentMethod::Cash,
//!         Money::new(usd, 1_090),
//!     )?,
//!     at: Timestamp::from_millis(1_004),
//! })?;
//! order.apply(OrderCommand::CloseCheck {
//!     operation_id: OperationId::new("op-5")?,
//!     check_id: check_id.clone(),
//!     at: Timestamp::from_millis(1_005),
//! })?;
//! assert_eq!(order.check(&check_id).unwrap().status(), CheckStatus::Closed);
//! # Ok(())
//! # }
//! ```

pub mod audit;
pub mod book;
pub mod catalog;
pub mod check;
pub mod device;
pub mod envelope;
pub mod error;
pub mod escpos;
pub mod guard;
pub mod ids;
pub mod intent;
pub mod kds;
pub mod line_item;
pub mod localization;
pub mod money;
pub mod numbering;
pub mod order;
pub mod ownership;
pub mod printer;
pub mod receipt;
pub mod rounding;
pub mod scale;
pub mod scanner;
pub mod settlement;
pub mod shift;
pub mod staff;
pub mod tax;
pub mod tip;

pub use audit::{AuditEvent, AuditEventKind, Timestamp};
pub use book::{BookAuditEvent, BookAuditKind, BookOp, BookOpKind, PaymentAllocation, PosBook};
pub use catalog::{
    CatalogItem, CatalogModifier, CatalogVersion, EffectiveWindow, MenuLink, PriceBookVersion,
    PricedCatalog, RecipeLink, TaxApplicability, TaxRule, TaxTableVersion, VersionAuditEvent,
    VersionAuditEventKind, VersionPin, VersionRef, VersionStore,
};
pub use check::{
    Check, CheckStatus, CheckTotals, PaymentLink, PaymentMethod, PaymentStatus, Refund, VoidRecord,
};
pub use device::DeviceTransport;
pub use envelope::{
    EnvelopeAction, EnvelopeCode, EnvelopeError, EnvelopePolicy, PaymentDesk, PaymentEnvelope,
    PaymentError, PaymentOutcome, TerminalEpoch,
};
pub use error::PosError;
pub use escpos::{
    decode_status, decode_status_response, Alignment, BarcodeType, CodePage, CutMode, DrawerPin,
    EscPosCodec, EscPosError, PrinterErrorCode, PrinterStatus, QrEcc, QrOptions, StatusFlags,
    StatusKind, MAX_BARCODE_BYTES, MAX_JOB_BYTES, MAX_QR_DATA_BYTES, MAX_STATUS_RESPONSE_BYTES,
    MAX_TEXT_BYTES,
};
pub use guard::{
    role_may_approve, Approval, ApprovalAction, ApprovalGuard, ApprovalSignature, ApprovalStatus,
    BusinessDay, DenialCode, DiscountCap, DiscountCaps, DiscountRequest, DiscountScope, GuardError,
    OperatorRole, RefundCaps, RefundRequest, SecurityAction, SecurityEvent, StackingPolicy,
    VoidRequest, VoidTarget, MILLIS_PER_DAY,
};
pub use ids::{
    ApprovalId, CashMovementId, CatalogItemId, CatalogVersionId, ChargebackId, CheckId, CustomerId,
    DrawerCountId, EmployeeId, IdempotencyKey, JurisdictionId, KdsTicketId, LineItemId, MenuId,
    ModifierId, OperationId, OrderId, PaymentId, PaymentIntentId, PaymentNonce, PriceBookVersionId,
    ProcessorRecordId, RecipeComponentId, RefundId, SettlementBatchId, ShiftId, StoreId,
    TaxTableVersionId, TerminalId, TipPoolId,
};
pub use intent::{
    CreateIntent, CreateOutcome, IntentBinding, IntentEvent, IntentStatus, PaymentIntent,
    PaymentIntentStore, ProcessorReport, ProcessorToken, ReconciliationOutcome, TransitionOutcome,
    MAX_PROCESSOR_TOKEN_LEN,
};
pub use kds::{
    KdsAck, KdsCodec, KdsCodecError, KdsEndpoint, KdsError, KdsLine, KdsSubmitOutcome, KdsTicket,
    KdsTransport, LineStatus, SimulatedKds, Station, TicketStatus, DEFAULT_KDS_ATTEMPTS,
    MAX_KDS_ACK_BYTES, MAX_KDS_LINES, MAX_KDS_TEXT_BYTES, MAX_KDS_TICKET_BYTES,
};
pub use line_item::{Discount, DiscountKind, LineItem, LineTotals, Modifier, TaxLine};
pub use localization::{
    CurrencyPlacement, DateOrder, Grouping, Locale, LocalizationError, ReceiptLabel, ReceiptLabels,
    TimeStyle,
};
pub use money::{Currency, Money, Quantity, Rate};
pub use numbering::{
    InvoiceError, InvoiceGap, InvoiceGapPolicy, InvoiceNumber, InvoiceRegister, InvoiceSeries,
    IssuedInvoice, MAX_INVOICE_WIDTH,
};
pub use order::{ApplyOutcome, ApplyReceipt, Order, OrderCommand};
pub use ownership::{Customer, Employee, EmployeeRole, Organization, Ownership, Store, Terminal};
pub use printer::{
    barcode_bytes, PrintOutcome, PrinterError, PrinterTransport, Receipt, ReceiptLine,
    ReceiptPrinter, SimulatedPrinter, TransportError, MAX_RECEIPT_LINES, MAX_RECEIPT_TEXT_BYTES,
    RECEIPT_WIDTH,
};
pub use receipt::{
    EmailAddress, Merchant, ReceiptCopy, ReceiptDocument, ReceiptError, ReceiptItemLine,
    ReceiptOutput, ReceiptPayment, ReceiptTotals, RenderedReceipt, MAX_MERCHANT_ADDRESS_LINES,
    MAX_RECEIPT_ITEM_LINES, RECEIPT_DOCUMENT_WIDTH,
};
pub use rounding::{div_round, RoundingMode};
pub use scale::{
    ScaleCodec, ScaleConfig, ScaleEndpoint, ScaleError, ScaleFault, ScaleFrameError, ScaleMode,
    ScaleProtocol, ScaleReading, ScaleUpdate, SimulatedScale, Weight, WeightUnit,
    DEFAULT_SCALE_TIMEOUT_MS, DEFAULT_STABLE_SAMPLES, MAX_SCALE_BUFFER_BYTES,
    MAX_SCALE_FRAME_BYTES, MAX_SCALE_READ_BYTES, MAX_WEIGHT_THOUSANDTHS,
};
pub use scanner::{
    Gs1Data, Gs1Element, Gs1Error, HidKey, HidScanner, HidTransport, ScannedCode, ScannerChecksum,
    ScannerCodec, ScannerError, ScannerFrameError, ScannerFraming, SerialScanner, SimulatedScanner,
    Symbology, DEFAULT_SCAN_READS, GS1_SEPARATOR, MAX_GS1_ELEMENTS, MAX_GS1_ELEMENT_BYTES,
    MAX_SCAN_FRAME_BYTES, MAX_SCAN_KEYS, MAX_SCAN_PAYLOAD_BYTES,
};
pub use settlement::{
    BatchStatus, BatchTotals, Chargeback, ChargebackBook, ChargebackChange, ChargebackSpec,
    ChargebackState, Evidence, EvidenceKind, EvidenceRef, ExceptionCategory, ExceptionKey,
    ExceptionQueue, ExceptionState, IngestOutcome, Processor, ProcessorBatchFile, ProcessorRecord,
    ProcessorRecordKind, SettlementBatch, SettlementBook, SettlementDay, SettlementError,
    SettlementException, SettlementKey, SettlementMatch, SettlementReconciliation,
    MAX_BATCH_RECORDS, MAX_CHARGEBACK_EVIDENCE, MAX_SETTLEMENT_TEXT_LEN,
};
pub use shift::{
    CashMovement, CashMovementKind, CashVariance, DrawerCount, ReconcileReport, ReportKind,
    SaleRecord, Shift, ShiftBook, ShiftChange, ShiftError, ShiftEvent, ShiftEventBody,
    ShiftRejection, ShiftReport, ShiftSpec, ShiftTotals,
};
pub use staff::{
    BadgeRef, EmployeeAccess, EmployeeDirectory, Permission, PermissionSet, PinRef, StaffError,
    StaffSession,
};
pub use tax::{
    TaxBreakdown, TaxClassification, TaxComponent, TaxComponentAmount, TaxEngine, TaxError,
    TaxPricing, TaxProfile, TaxTreatment, MAX_TAX_COMPONENTS,
};
pub use tip::{
    TipAdjustment, TipAllocation, TipChange, TipEntry, TipError, TipLedger, TipMember, TipPayout,
    TipPoolPolicy, MAX_TIP_NOTE_LEN, MAX_TIP_WEIGHT,
};
