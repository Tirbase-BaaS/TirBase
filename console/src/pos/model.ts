// SPDX-License-Identifier: Apache-2.0

// Terminal domain model for the operator console.
//
// This is an independent Apache-2.0 implementation. It imports no AGPL crate
// and mirrors no upstream source: checks, tenders, splits, shifts and kitchen
// tickets are plain values so the register keeps working with no network.
// Money is an integer count of minor units; there is no floating-point money.

export type Minor = number;
export type Station = 'kitchen' | 'bar' | 'cold';
export type Tender = 'cash' | 'card';
export type CheckStatus = 'open' | 'paid' | 'refunded' | 'voided';

export const STATIONS: Station[] = ['kitchen', 'bar', 'cold'];
export const TABLES: string[] = ['counter', 't1', 't2', 't3', 't4', 't5', 't6', 't7', 't8'];

export type MenuItem = {
  sku: string;
  name: string;
  priceMinor: Minor;
  station: Station;
  /** Tax rate in basis points, added on top of the line price. */
  taxBps: number;
};

export const MENU: MenuItem[] = [
  { sku: 'ESP-1', name: 'Espresso', priceMinor: 250, station: 'bar', taxBps: 1000 },
  { sku: 'LAT-1', name: 'Latte', priceMinor: 380, station: 'bar', taxBps: 1000 },
  { sku: 'TEA-1', name: 'Tea', priceMinor: 300, station: 'bar', taxBps: 1000 },
  { sku: 'CRS-1', name: 'Croissant', priceMinor: 280, station: 'kitchen', taxBps: 1000 },
  { sku: 'SAN-1', name: 'Sandwich', priceMinor: 650, station: 'kitchen', taxBps: 1000 },
  { sku: 'SAL-1', name: 'Salad bowl', priceMinor: 890, station: 'cold', taxBps: 1000 },
  { sku: 'CAK-1', name: 'Cake slice', priceMinor: 420, station: 'cold', taxBps: 1000 },
  { sku: 'WAT-1', name: 'Water', priceMinor: 180, station: 'bar', taxBps: 1000 },
];

export type Line = {
  id: string;
  sku: string;
  name: string;
  unitPriceMinor: Minor;
  quantity: number;
  station: Station;
  taxBps: number;
  voided: boolean;
  voidReason?: string;
};

export type Payment = {
  tender: Tender;
  amountMinor: Minor;
  tenderedMinor: Minor;
  changeMinor: Minor;
  at: number;
};

export type Refund = {
  id: string;
  amountMinor: Minor;
  reason: string;
  tender: Tender;
  at: number;
};

export type Check = {
  id: string;
  number: number;
  tableId: string;
  guestCount: number;
  openedAt: number;
  closedAt?: number;
  lines: Line[];
  tipMinor: Minor;
  status: CheckStatus;
  voidReason?: string;
  payment?: Payment;
  refunds: Refund[];
  revision: number;
};

export type Totals = {
  subtotalMinor: Minor;
  taxMinor: Minor;
  tipMinor: Minor;
  totalMinor: Minor;
  paidMinor: Minor;
  refundedMinor: Minor;
  balanceMinor: Minor;
};

export type TicketStatus = 'queued' | 'ready' | 'served';
export type TicketItemStatus = 'queued' | 'ready';

export type TicketItem = {
  id: string;
  lineId: string;
  name: string;
  quantity: number;
  status: TicketItemStatus;
};

export type Ticket = {
  id: string;
  checkId: string;
  number: number;
  tableId: string;
  station: Station;
  createdAt: number;
  status: TicketStatus;
  items: TicketItem[];
  bumpedAt?: number;
  recalledAt?: number;
  recallCount: number;
};

export type MovementKind = 'cash-in' | 'cash-out' | 'safe-drop';

export type Movement = {
  id: string;
  kind: MovementKind;
  amountMinor: Minor;
  at: number;
};

export type DrawerCount = {
  id: string;
  countedMinor: Minor;
  expectedMinor: Minor;
  varianceMinor: Minor;
  operator: string;
  at: number;
};

export type Shift = {
  id: string;
  operator: string;
  openedAt: number;
  openingFloatMinor: Minor;
  movements: Movement[];
  counts: DrawerCount[];
  closedAt?: number;
  closingVarianceMinor?: Minor;
};

export class PosError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'PosError';
    this.code = code;
  }
}

let sequence = 0;

/** A local identifier. Nothing here is used as a security decision. */
export function uid(prefix: string): string {
  sequence += 1;
  return `${prefix}-${Date.now().toString(36)}-${sequence.toString(36)}`;
}

export function lineBase(line: Line): Minor {
  return line.unitPriceMinor * line.quantity;
}

export function roundHalfUp(numerator: number, denominator: number): number {
  return Math.floor((numerator + denominator / 2) / denominator);
}

export function lineTax(line: Line): Minor {
  return roundHalfUp(lineBase(line) * line.taxBps, 10_000);
}

export function computeTotals(check: Check): Totals {
  let subtotal = 0;
  let tax = 0;
  for (const line of check.lines) {
    if (line.voided) continue;
    subtotal += lineBase(line);
    tax += lineTax(line);
  }
  const total = subtotal + tax + check.tipMinor;
  const paid = check.payment?.amountMinor ?? 0;
  const refunded = check.refunds.reduce((sum, refund) => sum + refund.amountMinor, 0);
  return {
    subtotalMinor: subtotal,
    taxMinor: tax,
    tipMinor: check.tipMinor,
    totalMinor: total,
    paidMinor: paid,
    refundedMinor: refunded,
    balanceMinor: check.status === 'open' ? total : Math.max(0, total - paid),
  };
}

export function activeLines(check: Check): Line[] {
  return check.lines.filter((line) => !line.voided);
}

function touch(check: Check, patch: Partial<Check>): Check {
  return { ...check, ...patch, revision: check.revision + 1 };
}

function requireOpen(check: Check): void {
  if (check.status !== 'open') {
    throw new PosError('check.not_open', `Check ${check.number} is ${check.status}`);
  }
}

export function newCheck(input: {
  number: number;
  tableId: string;
  guestCount?: number;
  at: number;
}): Check {
  return {
    id: uid('check'),
    number: input.number,
    tableId: input.tableId,
    guestCount: input.guestCount ?? 0,
    openedAt: input.at,
    lines: [],
    tipMinor: 0,
    status: 'open',
    refunds: [],
    revision: 1,
  };
}

export function addLine(check: Check, item: MenuItem, quantity = 1): Check {
  requireOpen(check);
  if (!Number.isInteger(quantity) || quantity < 1) {
    throw new PosError('quantity.invalid', 'Quantity must be a whole number of at least one');
  }
  const existing = check.lines.find((line) => !line.voided && line.sku === item.sku);
  if (existing) {
    return touch(check, {
      lines: check.lines.map((line) =>
        line.id === existing.id ? { ...line, quantity: line.quantity + quantity } : line,
      ),
    });
  }
  const line: Line = {
    id: uid('line'),
    sku: item.sku,
    name: item.name,
    unitPriceMinor: item.priceMinor,
    quantity,
    station: item.station,
    taxBps: item.taxBps,
    voided: false,
  };
  return touch(check, { lines: [...check.lines, line] });
}

export function setLineQuantity(check: Check, lineId: string, quantity: number): Check {
  requireOpen(check);
  const line = check.lines.find((candidate) => candidate.id === lineId);
  if (!line) throw new PosError('line.not_found', 'That line is not on this check');
  if (!Number.isInteger(quantity) || quantity < 1) {
    throw new PosError('quantity.invalid', 'Quantity must be a whole number of at least one');
  }
  return touch(check, {
    lines: check.lines.map((candidate) =>
      candidate.id === lineId ? { ...candidate, quantity } : candidate,
    ),
  });
}

export function voidLine(check: Check, lineId: string, reason: string): Check {
  requireOpen(check);
  const trimmed = reason.trim();
  if (!trimmed) throw new PosError('reason.required', 'A void needs a reason');
  if (!check.lines.some((line) => line.id === lineId)) {
    throw new PosError('line.not_found', 'That line is not on this check');
  }
  return touch(check, {
    lines: check.lines.map((line) =>
      line.id === lineId
        ? { ...line, voided: true, voidReason: trimmed }
        : line,
    ),
  });
}

export function setTip(check: Check, tipMinor: Minor): Check {
  requireOpen(check);
  if (!Number.isInteger(tipMinor) || tipMinor < 0) {
    throw new PosError('tip.invalid', 'A tip must not be negative');
  }
  return touch(check, { tipMinor });
}

export function voidCheck(check: Check, reason: string, at: number): Check {
  requireOpen(check);
  const trimmed = reason.trim();
  if (!trimmed) throw new PosError('reason.required', 'A void needs a reason');
  return touch(check, { status: 'voided', voidReason: trimmed, closedAt: at });
}

export function payCheck(
  check: Check,
  tender: Tender,
  tenderedMinor: Minor,
  at: number,
): Check {
  requireOpen(check);
  const totals = computeTotals(check);
  if (totals.totalMinor <= 0) {
    throw new PosError('payment.empty', 'Add a line before taking payment');
  }
  const tendered = tender === 'cash' ? tenderedMinor : totals.totalMinor;
  if (!Number.isInteger(tendered) || tendered < totals.totalMinor) {
    throw new PosError('payment.insufficient', 'Tendered amount is below the total');
  }
  return touch(check, {
    status: 'paid',
    closedAt: at,
    payment: {
      tender,
      amountMinor: totals.totalMinor,
      tenderedMinor: tendered,
      changeMinor: tendered - totals.totalMinor,
      at,
    },
  });
}

export function refundCheck(
  check: Check,
  amountMinor: Minor,
  reason: string,
  at: number,
): Check {
  if (check.status !== 'paid' && check.status !== 'refunded') {
    throw new PosError('refund.not_paid', 'Only a paid check can be refunded');
  }
  const trimmed = reason.trim();
  if (!trimmed) throw new PosError('reason.required', 'A refund needs a reason');
  const paid = check.payment?.amountMinor ?? 0;
  const already = check.refunds.reduce((sum, refund) => sum + refund.amountMinor, 0);
  if (!Number.isInteger(amountMinor) || amountMinor <= 0) {
    throw new PosError('refund.invalid', 'Refund must be a positive amount');
  }
  if (amountMinor > paid - already) {
    throw new PosError('refund.exceeds', 'Refund is larger than the unrefunded amount');
  }
  const refunds: Refund[] = [
    ...check.refunds,
    {
      id: uid('refund'),
      amountMinor,
      reason: trimmed,
      tender: check.payment?.tender ?? 'cash',
      at,
    },
  ];
  const refunded = already + amountMinor;
  return touch(check, {
    refunds,
    status: refunded >= paid ? 'refunded' : 'paid',
  });
}

export function transferCheck(check: Check, tableId: string): Check {
  requireOpen(check);
  if (tableId === check.tableId) {
    throw new PosError('transfer.same_table', 'The check is already on that table');
  }
  return touch(check, { tableId });
}

/** Split a check into `ways` checks, keeping one on the original. */
export function splitEvenly(
  check: Check,
  ways: number,
  at: number,
  nextNumber: () => number,
): { source: Check; splits: Check[] } {
  requireOpen(check);
  if (!Number.isInteger(ways) || ways < 2) {
    throw new PosError('split.invalid', 'Split into at least two checks');
  }
  const movable = activeLines(check);
  if (movable.length < ways) {
    throw new PosError('split.invalid', 'Not enough lines for that many checks');
  }

  const buckets: Line[][] = Array.from({ length: ways }, () => []);
  const sums: number[] = Array.from({ length: ways }, () => 0);
  const ordered = [...movable].sort((a, b) => lineBase(b) - lineBase(a));
  for (const line of ordered) {
    let target = 0;
    for (let index = 1; index < ways; index += 1) {
      if ((sums[index] ?? 0) < (sums[target] ?? 0)) target = index;
    }
    buckets[target]?.push(line);
    sums[target] = (sums[target] ?? 0) + lineBase(line);
  }

  const kept = new Set((buckets[0] ?? []).map((line) => line.id));
  const source: Check = touch(check, {
    lines: check.lines.filter((line) => line.voided || kept.has(line.id)),
  });
  const splits: Check[] = buckets.slice(1).map((lines) => {
    const ids = new Set(lines.map((line) => line.id));
    return {
      id: uid('check'),
      number: nextNumber(),
      tableId: check.tableId,
      guestCount: 0,
      openedAt: at,
      lines: check.lines.filter((line) => ids.has(line.id)),
      tipMinor: 0,
      status: 'open',
      refunds: [],
      revision: 1,
    };
  });
  return { source, splits };
}

/** Move part (or all) of one line onto a new check. */
export function splitLine(
  check: Check,
  lineId: string,
  quantity: number,
  at: number,
  nextNumber: () => number,
): { source: Check; split: Check } {
  requireOpen(check);
  const line = check.lines.find((candidate) => candidate.id === lineId);
  if (!line || line.voided) throw new PosError('line.not_found', 'That line is not on this check');
  if (!Number.isInteger(quantity) || quantity < 1 || quantity >= line.quantity) {
    throw new PosError('split.invalid', 'Split quantity must be at least one and below the line');
  }
  const source = touch(check, {
    lines: check.lines.map((candidate) =>
      candidate.id === lineId
        ? { ...candidate, quantity: candidate.quantity - quantity }
        : candidate,
    ),
  });
  const split: Check = {
    id: uid('check'),
    number: nextNumber(),
    tableId: check.tableId,
    guestCount: 0,
    openedAt: at,
    lines: [{ ...line, id: uid('line'), quantity }],
    tipMinor: 0,
    status: 'open',
    refunds: [],
    revision: 1,
  };
  return { source, split };
}

// ---------------------------------------------------------------------------
// Kitchen display
// ---------------------------------------------------------------------------

export function ticketsForCheck(check: Check, at: number): Ticket[] {
  const groups = new Map<Station, Line[]>();
  for (const line of check.lines) {
    if (line.voided) continue;
    const current = groups.get(line.station) ?? [];
    current.push(line);
    groups.set(line.station, current);
  }
  return STATIONS.flatMap((station) => {
    const lines = groups.get(station);
    if (!lines || lines.length === 0) return [];
    return [
      {
        id: uid('ticket'),
        checkId: check.id,
        number: check.number,
        tableId: check.tableId,
        station,
        createdAt: at,
        status: 'queued' as TicketStatus,
        items: lines.map((line) => ({
          id: uid('ticket-item'),
          lineId: line.id,
          name: line.name,
          quantity: line.quantity,
          status: 'queued' as TicketItemStatus,
        })),
        recallCount: 0,
      },
    ];
  });
}

export function allItemsReady(ticket: Ticket): boolean {
  return ticket.items.every((item) => item.status === 'ready');
}

export function bumpItem(ticket: Ticket, itemId: string): Ticket {
  if (ticket.status === 'served') {
    throw new PosError('ticket.served', 'A served ticket must be recalled first');
  }
  const items = ticket.items.map((item) =>
    item.id === itemId ? { ...item, status: 'ready' as TicketItemStatus } : item,
  );
  const next: Ticket = { ...ticket, items };
  return { ...next, status: allItemsReady(next) ? 'ready' : 'queued' };
}

export function bumpTicket(ticket: Ticket, at: number): Ticket {
  if (ticket.status === 'served') {
    throw new PosError('ticket.served', 'That ticket is already served');
  }
  return {
    ...ticket,
    status: 'served',
    items: ticket.items.map((item) => ({ ...item, status: 'ready' as TicketItemStatus })),
    bumpedAt: at,
  };
}

export function recallTicket(ticket: Ticket, at: number): Ticket {
  if (ticket.status !== 'served') {
    throw new PosError('ticket.recall', 'Only a served ticket can be recalled');
  }
  const ready = allItemsReady(ticket);
  return {
    ...ticket,
    status: ready ? 'ready' : 'queued',
    bumpedAt: undefined,
    recalledAt: at,
    recallCount: ticket.recallCount + 1,
  };
}

// ---------------------------------------------------------------------------
// Shift and drawer
// ---------------------------------------------------------------------------

export function openShift(input: {
  operator: string;
  floatMinor: Minor;
  at: number;
}): Shift {
  if (!Number.isInteger(input.floatMinor) || input.floatMinor < 0) {
    throw new PosError('shift.float', 'Opening float must not be negative');
  }
  return {
    id: uid('shift'),
    operator: input.operator,
    openedAt: input.at,
    openingFloatMinor: input.floatMinor,
    movements: [],
    counts: [],
  };
}

export function shiftMovements(shift: Shift, kind: MovementKind): Minor {
  return shift.movements
    .filter((movement) => movement.kind === kind)
    .reduce((sum, movement) => sum + movement.amountMinor, 0);
}

export function addMovement(shift: Shift, kind: MovementKind, amountMinor: Minor, at: number): Shift {
  if (shift.closedAt !== undefined) throw new PosError('shift.closed', 'The shift is closed');
  if (!Number.isInteger(amountMinor) || amountMinor <= 0) {
    throw new PosError('shift.amount', 'Amount must be a positive whole number of minor units');
  }
  return {
    ...shift,
    movements: [...shift.movements, { id: uid('movement'), kind, amountMinor, at }],
  };
}

export function cashSalesMinor(checks: Check[], shift: Shift): Minor {
  const from = shift.openedAt;
  return checks
    .filter(
      (check) =>
        check.payment?.tender === 'cash' &&
        check.payment.at >= from &&
        (shift.closedAt === undefined || check.payment.at <= shift.closedAt),
    )
    .reduce((sum, check) => sum + (check.payment?.amountMinor ?? 0), 0);
}

export function cashRefundsMinor(checks: Check[], shift: Shift): Minor {
  const from = shift.openedAt;
  return checks
    .flatMap((check) => check.refunds)
    .filter((refund) => refund.tender === 'cash' && refund.at >= from)
    .reduce((sum, refund) => sum + refund.amountMinor, 0);
}

export function expectedCashMinor(shift: Shift, checks: Check[]): Minor {
  return (
    shift.openingFloatMinor +
    shiftMovements(shift, 'cash-in') -
    shiftMovements(shift, 'cash-out') -
    shiftMovements(shift, 'safe-drop') +
    cashSalesMinor(checks, shift) -
    cashRefundsMinor(checks, shift)
  );
}

export function countDrawer(
  shift: Shift,
  countedMinor: Minor,
  operator: string,
  at: number,
  checks: Check[],
): { shift: Shift; count: DrawerCount } {
  if (shift.closedAt !== undefined) throw new PosError('shift.closed', 'The shift is closed');
  if (!Number.isInteger(countedMinor) || countedMinor < 0) {
    throw new PosError('shift.amount', 'Counted cash must not be negative');
  }
  const expected = expectedCashMinor(shift, checks);
  const count: DrawerCount = {
    id: uid('count'),
    countedMinor,
    expectedMinor: expected,
    varianceMinor: countedMinor - expected,
    operator,
    at,
  };
  return { shift: { ...shift, counts: [...shift.counts, count] }, count };
}

export function closeShift(
  shift: Shift,
  countedMinor: Minor,
  operator: string,
  at: number,
  checks: Check[],
): Shift {
  const counted = countDrawer(shift, countedMinor, operator, at, checks);
  return {
    ...counted.shift,
    closedAt: at,
    closingVarianceMinor: counted.count.varianceMinor,
  };
}

export function formatVariance(varianceMinor: Minor): string {
  const sign = varianceMinor > 0 ? '+' : '';
  return `${sign}${(varianceMinor / 100).toFixed(2)}`;
}

// ---------------------------------------------------------------------------
// Split allocation helper (kept pure for tests)
// ---------------------------------------------------------------------------

/**
 * Split `totalMinor` across `weights` without losing or inventing a minor unit.
 * Each share is the floor of its weighted part; the leftover minor units go one
 * each to the largest remainders, ties broken by position.
 */
export function allocateMinor(totalMinor: Minor, weights: number[]): Minor[] {
  if (weights.length === 0) throw new PosError('split.invalid', 'No shares to allocate');
  const sum = weights.reduce((acc, weight) => acc + weight, 0);
  if (sum <= 0) throw new PosError('split.invalid', 'Weights must be positive');
  const shares = weights.map((weight) => Math.floor((totalMinor * weight) / sum));
  const remainders = weights.map((weight, index) => ({
    remainder: (totalMinor * weight) % sum,
    index,
  }));
  remainders.sort((left, right) =>
    right.remainder - left.remainder || left.index - right.index,
  );
  let leftover = totalMinor - shares.reduce((acc, share) => acc + share, 0);
  for (const { index } of remainders) {
    if (leftover <= 0) break;
    shares[index] = (shares[index] ?? 0) + 1;
    leftover -= 1;
  }
  return shares;
}
