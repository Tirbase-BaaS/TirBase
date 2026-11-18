// SPDX-License-Identifier: Apache-2.0

// Local-first register state: checks, kitchen tickets and the open shift are
// device-owned and persisted in this browser, so a cashier can trade with no
// network at all. Completed sales are queued and pushed to the documented admin
// API when the link is up; a rejected push becomes a conflict the operator has
// to resolve explicitly.
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { errorMessage } from '../api';
import { useApi } from '../hooks';
import { useSession } from '../session';
import * as pos from './model';

const STORAGE_KEY = 'tirbase.console.pos.v1';

export type QueuedSale = {
  id: string;
  checkId: string;
  number: number;
  currency: string;
  totalMinor: number;
  lines: { sku: string; quantity: number; unit_price_minor: number }[];
  at: number;
};

export type PosConflict =
  | {
      id: string;
      kind: 'table-occupied';
      checkId: string;
      tableId: string;
      occupantNumber: number;
    }
  | { id: string; kind: 'sale-rejected'; saleId: string; message: string };

export type PosState = {
  version: 1;
  currency: string;
  operator: string;
  checks: pos.Check[];
  tickets: pos.Ticket[];
  shift?: pos.Shift;
  queue: QueuedSale[];
  conflicts: PosConflict[];
  selectedCheckId?: string;
  nextNumber: number;
};

function initialState(): PosState {
  return {
    version: 1,
    currency: 'EUR',
    operator: 'Cashier',
    checks: [],
    tickets: [],
    queue: [],
    conflicts: [],
    nextNumber: 101,
  };
}

function loadState(): PosState {
  const fallback = initialState();
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as Partial<PosState>;
    if (parsed.version !== 1) return fallback;
    return {
      ...fallback,
      currency: typeof parsed.currency === 'string' ? parsed.currency : fallback.currency,
      operator: typeof parsed.operator === 'string' ? parsed.operator : fallback.operator,
      checks: Array.isArray(parsed.checks) ? parsed.checks : [],
      tickets: Array.isArray(parsed.tickets) ? parsed.tickets : [],
      shift: parsed.shift,
      queue: Array.isArray(parsed.queue) ? parsed.queue : [],
      conflicts: Array.isArray(parsed.conflicts) ? parsed.conflicts : [],
      selectedCheckId: parsed.selectedCheckId,
      nextNumber:
        typeof parsed.nextNumber === 'number' && parsed.nextNumber > 0
          ? parsed.nextNumber
          : fallback.nextNumber,
    };
  } catch {
    return fallback;
  }
}

function saveState(state: PosState): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // A full or unavailable storage must never stop a sale; the state stays in
    // memory for this session.
  }
}

function replaceCheck(state: PosState, next: pos.Check): PosState {
  return {
    ...state,
    checks: state.checks.map((check) => (check.id === next.id ? next : check)),
    selectedCheckId: next.id,
  };
}

function queuedSale(check: pos.Check, currency: string, at: number): QueuedSale {
  return {
    id: `sale-${check.id}`,
    checkId: check.id,
    number: check.number,
    currency,
    totalMinor: pos.computeTotals(check).totalMinor,
    lines: pos.activeLines(check).map((line) => ({
      sku: line.sku,
      quantity: line.quantity,
      unit_price_minor: line.unitPriceMinor,
    })),
    at,
  };
}

export type PosValue = {
  state: PosState;
  online: boolean;
  linkUp: boolean;
  forcedOffline: boolean;
  selectedCheck?: pos.Check;
  setForcedOffline: (value: boolean) => void;
  setOperator: (name: string) => void;
  selectCheck: (id: string) => void;
  openCheck: (tableId: string, guestCount?: number) => pos.Check;
  closeCheck: () => void;
  addItem: (item: pos.MenuItem, tableId?: string) => void;
  changeQuantity: (lineId: string, quantity: number) => void;
  voidLine: (lineId: string, reason: string) => void;
  voidCheck: (reason: string) => void;
  setTip: (minor: number) => void;
  pay: (tender: pos.Tender, tenderedMinor: number) => pos.Check;
  refund: (amountMinor: number, reason: string) => void;
  splitEvenly: (ways: number) => void;
  splitLine: (lineId: string, quantity: number) => void;
  transfer: (tableId: string) => void;
  openShift: (floatMinor: number) => void;
  addMovement: (kind: pos.MovementKind, amountMinor: number) => void;
  closeShift: (countedMinor: number) => void;
  bumpTicket: (ticketId: string) => void;
  bumpItem: (ticketId: string, itemId: string) => void;
  recallTicket: (ticketId: string) => void;
  flush: () => Promise<void>;
  resolveConflict: (conflictId: string, action: 'move-anyway' | 'cancel' | 'retry' | 'discard') => void;
};

const PosContext = createContext<PosValue | null>(null);

export function PosProvider({ children }: { children: ReactNode }) {
  const api = useApi();
  const { config } = useSession();
  const [state, setState] = useState<PosState>(loadState);
  const [forcedOffline, setForcedOffline] = useState(false);
  const [online, setOnline] = useState(() => (typeof navigator === 'undefined' ? true : navigator.onLine !== false));

  const stateRef = useRef(state);
  useEffect(() => {
    stateRef.current = state;
  }, [state]);

  useEffect(() => {
    saveState(state);
  }, [state]);

  useEffect(() => {
    const goOnline = () => setOnline(true);
    const goOffline = () => setOnline(false);
    window.addEventListener('online', goOnline);
    window.addEventListener('offline', goOffline);
    return () => {
      window.removeEventListener('online', goOnline);
      window.removeEventListener('offline', goOffline);
    };
  }, []);

  const linkUp = online && !forcedOffline;

  const selectedCheck = useMemo(
    () => state.checks.find((check) => check.id === state.selectedCheckId),
    [state.checks, state.selectedCheckId],
  );

  const openCheck = useCallback((tableId: string, guestCount = 0) => {
    const current = stateRef.current;
    const check = pos.newCheck({
      number: current.nextNumber,
      tableId,
      guestCount,
      at: Date.now(),
    });
    setState({
      ...current,
      checks: [...current.checks, check],
      selectedCheckId: check.id,
      nextNumber: current.nextNumber + 1,
    });
    return check;
  }, []);

  const requireSelectedOpen = (): pos.Check => {
    const check = stateRef.current.checks.find(
      (candidate) => candidate.id === stateRef.current.selectedCheckId,
    );
    if (!check) throw new pos.PosError('check.none', 'Select or open a check first');
    if (check.status !== 'open') {
      throw new pos.PosError('check.not_open', 'That check is already closed');
    }
    return check;
  };

  const addItem = useCallback((item: pos.MenuItem, tableId = 'counter') => {
    setState((current) => {
      const selected = current.checks.find(
        (candidate) =>
          candidate.id === current.selectedCheckId && candidate.status === 'open',
      );
      if (selected) return replaceCheck(current, pos.addLine(selected, item));
      const opened = pos.newCheck({
        number: current.nextNumber,
        tableId,
        at: Date.now(),
      });
      const updated = pos.addLine(opened, item);
      return {
        ...current,
        checks: [...current.checks, updated],
        selectedCheckId: updated.id,
        nextNumber: current.nextNumber + 1,
      };
    });
  }, []);

  const changeQuantity = useCallback((lineId: string, quantity: number) => {
    const check = requireSelectedOpen();
    setState((current) => replaceCheck(current, pos.setLineQuantity(check, lineId, quantity)));
  }, []);

  const voidLine = useCallback((lineId: string, reason: string) => {
    const check = requireSelectedOpen();
    setState((current) => replaceCheck(current, pos.voidLine(check, lineId, reason)));
  }, []);

  const voidCheck = useCallback((reason: string) => {
    const check = requireSelectedOpen();
    setState((current) => replaceCheck(current, pos.voidCheck(check, reason, Date.now())));
  }, []);

  const setTip = useCallback((minor: number) => {
    const check = requireSelectedOpen();
    setState((current) => replaceCheck(current, pos.setTip(check, minor)));
  }, []);

  const pay = useCallback(
    (tender: pos.Tender, tenderedMinor: number) => {
      const check = requireSelectedOpen();
      const at = Date.now();
      const paid = pos.payCheck(check, tender, tenderedMinor, at);
      const tickets = pos.ticketsForCheck(paid, at);
      setState((current) => ({
        ...replaceCheck(current, paid),
        tickets: [...current.tickets, ...tickets],
        queue: [...current.queue, queuedSale(paid, current.currency, at)],
      }));
      return paid;
    },
    [],
  );

  const refund = useCallback((amountMinor: number, reason: string) => {
    const check = stateRef.current.checks.find(
      (candidate) => candidate.id === stateRef.current.selectedCheckId,
    );
    if (!check) throw new pos.PosError('check.none', 'Select a paid check first');
    const refunded = pos.refundCheck(check, amountMinor, reason, Date.now());
    setState((current) => replaceCheck(current, refunded));
  }, []);

  const splitEvenly = useCallback((ways: number) => {
    const check = requireSelectedOpen();
    const current = stateRef.current;
    let number = current.nextNumber;
    const nextNumber = () => {
      const value = number;
      number += 1;
      return value;
    };
    const { source, splits } = pos.splitEvenly(check, ways, Date.now(), nextNumber);
    setState({
      ...replaceCheck(current, source),
      checks: [
        ...current.checks.map((candidate) => (candidate.id === source.id ? source : candidate)),
        ...splits,
      ],
      nextNumber: number,
    });
  }, []);

  const splitLine = useCallback((lineId: string, quantity: number) => {
    const check = requireSelectedOpen();
    const current = stateRef.current;
    let number = current.nextNumber;
    const nextNumber = () => {
      const value = number;
      number += 1;
      return value;
    };
    const { source, split } = pos.splitLine(check, lineId, quantity, Date.now(), nextNumber);
    setState({
      ...replaceCheck(current, source),
      checks: [
        ...current.checks.map((candidate) => (candidate.id === source.id ? source : candidate)),
        split,
      ],
      nextNumber: number,
    });
  }, []);

  const transfer = useCallback((tableId: string) => {
    const check = requireSelectedOpen();
    const current = stateRef.current;
    const occupant = current.checks.find(
      (candidate) =>
        candidate.id !== check.id &&
        candidate.tableId === tableId &&
        candidate.status === 'open',
    );
    if (occupant) {
      const conflict: PosConflict = {
        id: pos.uid('conflict'),
        kind: 'table-occupied',
        checkId: check.id,
        tableId,
        occupantNumber: occupant.number,
      };
      setState({ ...current, conflicts: [...current.conflicts, conflict] });
      return;
    }
    setState(replaceCheck(current, pos.transferCheck(check, tableId)));
  }, []);

  const openShiftAction = useCallback((floatMinor: number) => {
    const current = stateRef.current;
    if (current.shift && current.shift.closedAt === undefined) {
      throw new pos.PosError('shift.open', 'A shift is already open');
    }
    setState({
      ...current,
      shift: pos.openShift({ operator: current.operator, floatMinor, at: Date.now() }),
    });
  }, []);

  const addMovement = useCallback((kind: pos.MovementKind, amountMinor: number) => {
    const current = stateRef.current;
    if (!current.shift) throw new pos.PosError('shift.none', 'Open a shift first');
    setState({
      ...current,
      shift: pos.addMovement(current.shift, kind, amountMinor, Date.now()),
    });
  }, []);

  const closeShift = useCallback((countedMinor: number) => {
    const current = stateRef.current;
    if (!current.shift) throw new pos.PosError('shift.none', 'Open a shift first');
    setState({
      ...current,
      shift: pos.closeShift(
        current.shift,
        countedMinor,
        current.operator,
        Date.now(),
        current.checks,
      ),
    });
  }, []);

  const bumpTicket = useCallback((ticketId: string) => {
    setState((current) => ({
      ...current,
      tickets: current.tickets.map((ticket) =>
        ticket.id === ticketId ? pos.bumpTicket(ticket, Date.now()) : ticket,
      ),
    }));
  }, []);

  const bumpItem = useCallback((ticketId: string, itemId: string) => {
    setState((current) => ({
      ...current,
      tickets: current.tickets.map((ticket) =>
        ticket.id === ticketId ? pos.bumpItem(ticket, itemId) : ticket,
      ),
    }));
  }, []);

  const recallTicket = useCallback((ticketId: string) => {
    setState((current) => ({
      ...current,
      tickets: current.tickets.map((ticket) =>
        ticket.id === ticketId ? pos.recallTicket(ticket, Date.now()) : ticket,
      ),
    }));
  }, []);

  const inFlight = useRef<Set<string>>(new Set());

  const flush = useCallback(async () => {
    const attempt = stateRef.current.queue;
    if (!linkUp || attempt.length === 0) return;
    for (const sale of attempt) {
      if (inFlight.current.has(sale.id)) continue;
      inFlight.current.add(sale.id);
      try {
        const order = await api.createOrder(config.tenant, sale.currency, sale.totalMinor);
        for (const line of sale.lines) {
          await api.createLine(config.tenant, order.id, line);
        }
        setState((current) => ({
          ...current,
          queue: current.queue.filter((queued) => queued.id !== sale.id),
        }));
      } catch (error) {
        const message = errorMessage(error);
        setState((current) => ({
          ...current,
          conflicts: current.conflicts.some(
            (conflict) => conflict.kind === 'sale-rejected' && conflict.saleId === sale.id,
          )
            ? current.conflicts
            : [
                ...current.conflicts,
                {
                  id: pos.uid('conflict'),
                  kind: 'sale-rejected' as const,
                  saleId: sale.id,
                  message,
                },
              ],
        }));
        break;
      } finally {
        inFlight.current.delete(sale.id);
      }
    }
  }, [api, config.tenant, linkUp]);

  useEffect(() => {
    if (linkUp && state.queue.length > 0) void flush();
  }, [linkUp, state.queue.length, flush]);

  const resolveConflict = useCallback(
    (conflictId: string, action: 'move-anyway' | 'cancel' | 'retry' | 'discard') => {
      const current = stateRef.current;
      const conflict = current.conflicts.find((entry) => entry.id === conflictId);
      if (!conflict) return;
      const rest = current.conflicts.filter((entry) => entry.id !== conflictId);
      if (conflict.kind === 'table-occupied') {
        if (action === 'move-anyway') {
          const check = current.checks.find((candidate) => candidate.id === conflict.checkId);
          if (check && check.status === 'open') {
            setState(replaceCheck({ ...current, conflicts: rest }, pos.transferCheck(check, conflict.tableId)));
            return;
          }
        }
        setState({ ...current, conflicts: rest });
        return;
      }
      if (action === 'discard') {
        setState({
          ...current,
          conflicts: rest,
          queue: current.queue.filter((sale) => sale.id !== conflict.saleId),
        });
        return;
      }
      setState({ ...current, conflicts: rest });
      void flush();
    },
    [flush],
  );

  const value = useMemo<PosValue>(
    () => ({
      state,
      online,
      linkUp,
      forcedOffline,
      selectedCheck,
      setForcedOffline,
      setOperator: (name: string) =>
        setState((current) => ({ ...current, operator: name.trim() || 'Cashier' })),
      selectCheck: (id: string) =>
        setState((current) => ({ ...current, selectedCheckId: id })),
      openCheck,
      closeCheck: () => setState((current) => ({ ...current, selectedCheckId: undefined })),
      addItem,
      changeQuantity,
      voidLine,
      voidCheck,
      setTip,
      pay,
      refund,
      splitEvenly,
      splitLine,
      transfer,
      openShift: openShiftAction,
      addMovement,
      closeShift,
      bumpTicket,
      bumpItem,
      recallTicket,
      flush,
      resolveConflict,
    }),
    [
      state,
      online,
      linkUp,
      forcedOffline,
      selectedCheck,
      openCheck,
      addItem,
      changeQuantity,
      voidLine,
      voidCheck,
      setTip,
      pay,
      refund,
      splitEvenly,
      splitLine,
      transfer,
      openShiftAction,
      addMovement,
      closeShift,
      bumpTicket,
      bumpItem,
      recallTicket,
      flush,
      resolveConflict,
    ],
  );

  return <PosContext.Provider value={value}>{children}</PosContext.Provider>;
}

export function usePos(): PosValue {
  const value = useContext(PosContext);
  if (!value) throw new Error('usePos must be used inside PosProvider');
  return value;
}
