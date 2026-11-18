// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useMemo, useState, type FormEvent } from 'react';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  InlineAlert,
  PageHeader,
  SelectField,
  Table,
  TextInput,
  type Column,
} from '@tirbase/console-design-system';
import { formatMoney, parseMoneyMinor } from '../format';
import { useI18n } from '../i18n';
import { useSession } from '../session';
import * as model from '../pos/model';
import { usePos } from '../pos/store';
import { ConflictPanel, OfflineBadge, Prompt, TableLabel } from '../pos/ui';

type PromptState =
  | { kind: 'void-line'; lineId: string }
  | { kind: 'void-check' }
  | { kind: 'split-ways' }
  | { kind: 'split-line'; lineId: string; max: number };

export function TerminalScreen({ tableParam }: { tableParam?: string }) {
  const { t, locale } = useI18n();
  const { config } = useSession();
  const {
    state,
    selectedCheck,
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
    openCheck,
    selectCheck,
  } = usePos();

  const tableId = useId();
  const tipId = useId();
  const tenderId = useId();
  const tenderedId = useId();
  const transferId = useId();
  const refundAmountId = useId();
  const refundReasonId = useId();

  const [table, setTable] = useState(tableParam ?? 'counter');
  const [tender, setTender] = useState<model.Tender>('cash');
  const [tendered, setTendered] = useState('');
  const [tip, setTipValue] = useState('');
  const [transferTo, setTransferTo] = useState('t1');
  const [refundAmount, setRefundAmount] = useState('');
  const [refundReason, setRefundReason] = useState('');
  const [prompt, setPrompt] = useState<PromptState>();
  const [notice, setNotice] = useState<string>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (tableParam) setTable(tableParam);
  }, [tableParam]);

  const money = (minor: number) => formatMoney(minor, state.currency, locale);
  const totals = selectedCheck ? model.computeTotals(selectedCheck) : undefined;
  const isOpen = selectedCheck?.status === 'open';
  const remaining = totals ? Math.max(0, totals.paidMinor - totals.refundedMinor) : 0;

  const run = (action: () => string | void, success?: string) => {
    try {
      const returned = action();
      setError(undefined);
      setNotice(typeof returned === 'string' ? returned : success);
    } catch (reason) {
      setNotice(undefined);
      setError(reason instanceof model.PosError ? reason.message : String(reason));
    }
  };

  const openChecks = useMemo(
    () => state.checks.filter((check) => check.status !== 'voided'),
    [state.checks],
  );

  const lineColumns: Column<model.Line>[] = [
    {
      key: 'item',
      header: t('terminal.item'),
      render: (line) => (
        <span className={line.voided ? 'tb-pos-voided' : undefined}>
          {line.name}
          {line.voided ? <Badge tone="warn">{t('terminal.voidedLine')}</Badge> : null}
        </span>
      ),
    },
    {
      key: 'quantity',
      header: t('terminal.qty'),
      render: (line) => (
        <div className="tb-inline">
          <Button
            variant="secondary"
            className="tb-touch tb-touch--square"
            aria-label={`${t('terminal.qty')} − ${line.name}`}
            disabled={line.voided || line.quantity < 2}
            onClick={() => run(() => changeQuantity(line.id, line.quantity - 1))}
          >
            −
          </Button>
          <span aria-live="polite">{line.quantity}</span>
          <Button
            variant="secondary"
            className="tb-touch tb-touch--square"
            aria-label={`${t('terminal.qty')} + ${line.name}`}
            disabled={line.voided}
            onClick={() => run(() => changeQuantity(line.id, line.quantity + 1))}
          >
            +
          </Button>
        </div>
      ),
    },
    {
      key: 'amount',
      header: t('terminal.price'),
      align: 'end',
      render: (line) => money(model.lineBase(line) + model.lineTax(line)),
    },
    {
      key: 'actions',
      header: t('common.actions'),
      align: 'end',
      render: (line) => (
        <div className="tb-inline tb-inline--end">
          <Button
            variant="secondary"
            className="tb-touch"
            disabled={line.voided || !isOpen}
            onClick={() => setPrompt({ kind: 'void-line', lineId: line.id })}
          >
            {t('terminal.void')}
          </Button>
          <Button
            variant="secondary"
            className="tb-touch"
            disabled={line.voided || !isOpen || line.quantity < 2}
            onClick={() =>
              setPrompt({ kind: 'split-line', lineId: line.id, max: line.quantity })
            }
          >
            {t('terminal.splitLine')}
          </Button>
        </div>
      ),
    },
  ];

  const onPay = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedCheck || !totals) return;
    const tenderedMinor =
      tender === 'cash' ? parseMoneyMinor(tendered) : totals.totalMinor;
    if (tenderedMinor === null) {
      setError(t('terminal.required'));
      return;
    }
    run(() => {
      const paid = pay(tender, tenderedMinor);
      setTendered('');
      return t('terminal.saleDone', { number: paid.number });
    });
  };

  const onRefund = () => {
    const amount = parseMoneyMinor(refundAmount);
    if (amount === null) {
      setError(t('terminal.required'));
      return;
    }
    if (!refundReason.trim()) {
      setError(t('terminal.refundReason'));
      return;
    }
    run(() => {
      refund(amount, refundReason);
      setRefundAmount('');
      setRefundReason('');
      return t('terminal.refundDone');
    });
  };

  return (
    <>
      <PageHeader
        eyebrow={config.tenant}
        title={t('terminal.title')}
        description={t('terminal.description')}
        actions={<OfflineBadge />}
      />

      <ConflictPanel />
      {notice ? <InlineAlert tone="success">{notice}</InlineAlert> : null}
      {error ? (
        <InlineAlert tone="error">
          {error} <span className="tb-muted">{t('terminal.errorHint')}</span>
        </InlineAlert>
      ) : null}

      {!state.shift || state.shift.closedAt !== undefined ? (
        <InlineAlert tone="info">
          {t('terminal.noShift')}{' '}
          <a className="tb-button tb-button--secondary tb-touch" href="#/shift">
            {t('shift.openShift')}
          </a>
        </InlineAlert>
      ) : null}

      <div className="tb-pos-grid">
        <Card title={t('terminal.menu')} description={t('terminal.menuHint')}>
          <div className="tb-menu-grid">
            {model.MENU.map((item) => (
              <button
                key={item.sku}
                type="button"
                className="tb-menu-tile tb-touch"
                onClick={() => run(() => addItem(item, table))}
              >
                <span className="tb-menu-tile__name">{item.name}</span>
                <span className="tb-menu-tile__price">{money(item.priceMinor)}</span>
                <span className="tb-menu-tile__station">{t(`station.${item.station}`)}</span>
              </button>
            ))}
          </div>
        </Card>

        <Card
          title={
            selectedCheck
              ? t('terminal.check', { number: selectedCheck.number })
              : t('terminal.check', { number: '—' })
          }
          description={
            selectedCheck
              ? selectedCheck.tableId === 'counter'
                ? t('terminal.counter')
                : selectedCheck.tableId.toUpperCase()
              : t('terminal.noChecksBody')
          }
          actions={
            selectedCheck?.status === 'open' ? (
              <Button
                variant="secondary"
                className="tb-touch"
                onClick={() => setPrompt({ kind: 'void-check' })}
              >
                {t('terminal.voidCheck')}
              </Button>
            ) : null
          }
        >
          <div className="tb-inline tb-inline--wrap">
            <SelectField
              label={t('terminal.table')}
              id={tableId}
              value={table}
              onChange={(event) => setTable(event.target.value)}
            >
              {model.TABLES.map((id) => (
                <option key={id} value={id}>
                  {id === 'counter' ? t('terminal.counter') : id.toUpperCase()}
                </option>
              ))}
            </SelectField>
            <Button
              className="tb-touch"
              onClick={() => {
                setNotice(undefined);
                setError(undefined);
                openCheck(table);
              }}
            >
              {t('terminal.startCheck')}
            </Button>
          </div>

          {openChecks.length > 0 ? (
            <div className="tb-check-strip" role="group" aria-label={t('terminal.openChecks')}>
              {openChecks.map((check) => (
                <button
                  key={check.id}
                  type="button"
                  className="tb-check-chip tb-touch"
                  aria-pressed={check.id === selectedCheck?.id}
                  onClick={() => selectCheck(check.id)}
                >
                  <strong>#{check.number}</strong>
                  <span>
                    <TableLabel id={check.tableId} />
                  </span>
                  <span>{money(model.computeTotals(check).totalMinor)}</span>
                  <span className="tb-check-chip__status">
                    {t(`terminal.status.${check.status}`)}
                  </span>
                </button>
              ))}
            </div>
          ) : null}

          {selectedCheck ? (
            selectedCheck.lines.length > 0 ? (
              <Table
                caption={t('terminal.lines')}
                columns={lineColumns}
                rows={selectedCheck.lines}
                rowKey={(line) => line.id}
              />
            ) : (
              <EmptyState
                title={t('terminal.noLines')}
                description={t('terminal.noLinesBody')}
              />
            )
          ) : (
            <EmptyState
              title={t('terminal.noChecks')}
              description={t('terminal.noChecksBody')}
            />
          )}

          {prompt ? (
            <Prompt
              title={
                prompt.kind === 'void-line'
                  ? t('terminal.voidLine')
                  : prompt.kind === 'void-check'
                    ? t('terminal.voidCheck')
                    : prompt.kind === 'split-ways'
                      ? t('terminal.splitCheck')
                      : t('terminal.splitLine')
              }
              label={
                prompt.kind === 'void-line' || prompt.kind === 'void-check'
                  ? t('terminal.voidReason')
                  : prompt.kind === 'split-ways'
                    ? t('terminal.splitWays')
                    : t('terminal.splitQuantity')
              }
              kind={
                prompt.kind === 'split-ways' || prompt.kind === 'split-line'
                  ? 'number'
                  : 'text'
              }
              defaultValue={
                prompt.kind === 'split-ways'
                  ? '2'
                  : prompt.kind === 'split-line'
                    ? '1'
                    : ''
              }
              confirmLabel={t('common.save')}
              onCancel={() => setPrompt(undefined)}
              onConfirm={(value) => {
                const active = prompt;
                setPrompt(undefined);
                run(() => {
                  if (active.kind === 'void-line') voidLine(active.lineId, value);
                  if (active.kind === 'void-check') {
                    voidCheck(value);
                    return t('terminal.checkVoided');
                  }
                  if (active.kind === 'split-ways') {
                    const ways = Number(value);
                    splitEvenly(ways);
                    return t('terminal.splitDone');
                  }
                  if (active.kind === 'split-line') {
                    splitLine(active.lineId, Number(value));
                    return t('terminal.splitDone');
                  }
                  return undefined;
                });
              }}
            />
          ) : null}

          {isOpen && selectedCheck ? (
            <div className="tb-inline tb-inline--wrap tb-pos-actions">
              {selectedCheck.lines.length >= 2 ? (
                <Button
                  variant="secondary"
                  className="tb-touch"
                  onClick={() => setPrompt({ kind: 'split-ways' })}
                >
                  {t('terminal.splitCheck')}
                </Button>
              ) : null}
              <SelectField
                label={t('terminal.transferTo')}
                id={transferId}
                value={transferTo}
                onChange={(event) => setTransferTo(event.target.value)}
              >
                {model.TABLES.filter((id) => id !== selectedCheck.tableId).map((id) => (
                  <option key={id} value={id}>
                    {id === 'counter' ? t('terminal.counter') : id.toUpperCase()}
                  </option>
                ))}
              </SelectField>
              <Button
                variant="secondary"
                className="tb-touch"
                onClick={() => run(() => transfer(transferTo))}
              >
                {t('terminal.transfer')}
              </Button>
            </div>
          ) : null}
        </Card>

        <Card title={t('terminal.totals')}>
          {totals ? (
            <>
              <dl className="tb-kv" aria-live="polite">
                <dt>{t('terminal.subtotal')}</dt>
                <dd>{money(totals.subtotalMinor)}</dd>
                <dt>{t('terminal.tax')}</dt>
                <dd>{money(totals.taxMinor)}</dd>
                <dt>{t('terminal.tip')}</dt>
                <dd>{money(totals.tipMinor)}</dd>
                <dt>
                  <strong>{t('terminal.total')}</strong>
                </dt>
                <dd>
                  <strong>{money(totals.totalMinor)}</strong>
                </dd>
                {totals.refundedMinor > 0 ? (
                  <>
                    <dt>{t('terminal.refundedLabel')}</dt>
                    <dd>{money(totals.refundedMinor)}</dd>
                  </>
                ) : null}
              </dl>

              {isOpen ? (
                <>
                  <form
                    className="tb-inline tb-inline--wrap tb-pos-tip"
                    onSubmit={(event) => {
                      event.preventDefault();
                      const minor = parseMoneyMinor(tip);
                      if (minor === null) {
                        setError(t('terminal.required'));
                        return;
                      }
                      run(() => setTip(minor), t('terminal.tipApplied'));
                      setTipValue('');
                    }}
                  >
                    <Field label={t('terminal.tip')} htmlFor={tipId}>
                      <TextInput
                        id={tipId}
                        type="number"
                        inputMode="decimal"
                        step="0.01"
                        min="0"
                        value={tip}
                        onChange={(event) => setTipValue(event.target.value)}
                      />
                    </Field>
                    <Button type="submit" variant="secondary" className="tb-touch">
                      {t('terminal.tipApply')}
                    </Button>
                  </form>

                  <form className="tb-pos-pay" onSubmit={onPay}>
                    <SelectField
                      label={t('terminal.tender')}
                      id={tenderId}
                      value={tender}
                      onChange={(event) => setTender(event.target.value as model.Tender)}
                    >
                      <option value="cash">{t('terminal.cash')}</option>
                      <option value="card">{t('terminal.card')}</option>
                    </SelectField>
                    {tender === 'cash' ? (
                      <Field label={t('terminal.tendered')} htmlFor={tenderedId}>
                        <TextInput
                          id={tenderedId}
                          type="number"
                          inputMode="decimal"
                          step="0.01"
                          min="0"
                          value={tendered}
                          onChange={(event) => setTendered(event.target.value)}
                        />
                      </Field>
                    ) : null}
                    <Button
                      type="submit"
                      className="tb-touch tb-touch--wide"
                      disabled={totals.totalMinor <= 0}
                    >
                      {t('terminal.pay', { total: money(totals.totalMinor) })}
                    </Button>
                  </form>
                </>
              ) : null}

              {selectedCheck?.payment ? (
                <dl className="tb-kv tb-pos-payment">
                  <dt>{t('terminal.paidLabel')}</dt>
                  <dd>{money(selectedCheck.payment.amountMinor)}</dd>
                  <dt>{t('terminal.tendered')}</dt>
                  <dd>{money(selectedCheck.payment.tenderedMinor)}</dd>
                  <dt>{t('terminal.change')}</dt>
                  <dd>{money(selectedCheck.payment.changeMinor)}</dd>
                </dl>
              ) : null}

              {remaining > 0 ? (
                <div className="tb-pos-refund">
                  <h3>{t('terminal.refund')}</h3>
                  <p className="tb-muted">
                    {t('terminal.remaining', { amount: money(remaining) })}
                  </p>
                  <Field label={t('terminal.refundAmount')} htmlFor={refundAmountId}>
                    <TextInput
                      id={refundAmountId}
                      type="number"
                      inputMode="decimal"
                      step="0.01"
                      min="0"
                      value={refundAmount}
                      onChange={(event) => setRefundAmount(event.target.value)}
                    />
                  </Field>
                  <Field label={t('terminal.refundReason')} htmlFor={refundReasonId}>
                    <TextInput
                      id={refundReasonId}
                      value={refundReason}
                      onChange={(event) => setRefundReason(event.target.value)}
                    />
                  </Field>
                  <Button variant="danger" className="tb-touch" onClick={onRefund}>
                    {t('terminal.refundAction')}
                  </Button>
                </div>
              ) : null}

              {selectedCheck?.status === 'voided' ? (
                <InlineAlert tone="error">
                  {t('terminal.checkVoided')} · {selectedCheck.voidReason}
                </InlineAlert>
              ) : null}
            </>
          ) : (
            <EmptyState
              title={t('terminal.noChecks')}
              description={t('terminal.selectFirst')}
            />
          )}
        </Card>
      </div>
    </>
  );
}
