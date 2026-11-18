// SPDX-License-Identifier: Apache-2.0
import { useId, useState } from 'react';
import {
  Badge,
  Button,
  Card,
  Field,
  InlineAlert,
  PageHeader,
  SelectField,
  Table,
  TextInput,
  type Column,
} from '@tirbase/console-design-system';
import { formatDateTime, formatMoney, parseMoneyMinor } from '../format';
import { useI18n } from '../i18n';
import { useSession } from '../session';
import * as model from '../pos/model';
import { usePos } from '../pos/store';
import { OfflineBadge } from '../pos/ui';

export function ShiftScreen() {
  const { t, locale } = useI18n();
  const { config } = useSession();
  const { state, openShift, addMovement, closeShift, setOperator } = usePos();

  const floatId = useId();
  const operatorId = useId();
  const amountId = useId();
  const kindId = useId();
  const countedId = useId();

  const [float, setFloat] = useState('100.00');
  const [operatorDraft, setOperatorDraft] = useState(state.operator);
  const [amount, setAmount] = useState('');
  const [kind, setKind] = useState<model.MovementKind>('cash-in');
  const [counted, setCounted] = useState('');
  const [notice, setNotice] = useState<string>();
  const [error, setError] = useState<string>();

  const shift = state.shift;
  const money = (minor: number) => formatMoney(minor, state.currency, locale);
  const time = (ms: number) => formatDateTime(ms / 1000, locale, config.timezone);

  const run = (action: () => void, success?: string) => {
    try {
      action();
      setError(undefined);
      setNotice(success);
    } catch (reason) {
      setNotice(undefined);
      setError(reason instanceof model.PosError ? reason.message : String(reason));
    }
  };

  const openingForm = (
    <Card title={t('shift.open')} description={t('shift.openHint')}>
      <div className="tb-form-grid">
        <Field label={t('shift.operator')} htmlFor={operatorId}>
          <TextInput
            id={operatorId}
            value={operatorDraft}
            onChange={(event) => setOperatorDraft(event.target.value)}
          />
        </Field>
        <Field label={t('shift.float')} htmlFor={floatId}>
          <TextInput
            id={floatId}
            type="number"
            inputMode="decimal"
            step="0.01"
            min="0"
            value={float}
            onChange={(event) => setFloat(event.target.value)}
          />
        </Field>
        <div className="tb-form-actions">
          <Button
            className="tb-touch"
            onClick={() => {
              const minor = parseMoneyMinor(float);
              if (minor === null) {
                setError(t('terminal.required'));
                return;
              }
              run(() => {
                setOperator(operatorDraft);
                openShift(minor);
              }, t('shift.opened'));
            }}
          >
            {t('shift.openShift')}
          </Button>
        </div>
      </div>
    </Card>
  );

  if (!shift) {
    return (
      <>
        <PageHeader
          eyebrow={config.tenant}
          title={t('shift.title')}
          description={t('shift.description')}
          actions={<OfflineBadge />}
        />
        {notice ? <InlineAlert tone="success">{notice}</InlineAlert> : null}
        {error ? <InlineAlert tone="error">{error}</InlineAlert> : null}
        <InlineAlert tone="info">{t('shift.noShift')}</InlineAlert>
        {openingForm}
      </>
    );
  }

  const isOpen = shift.closedAt === undefined;
  const expected = model.expectedCashMinor(shift, state.checks);
  const cashSales = model.cashSalesMinor(state.checks, shift);
  const cashRefunds = model.cashRefundsMinor(state.checks, shift);
  const lastCount = shift.counts[shift.counts.length - 1];
  const countedMinor = parseMoneyMinor(counted);

  const movementColumns: Column<model.Movement>[] = [
    { key: 'kind', header: t('shift.movement'), render: (movement) => t(`shift.kind.${movement.kind}`) },
    {
      key: 'amount',
      header: t('shift.amount'),
      align: 'end',
      render: (movement) => money(movement.amountMinor),
    },
    { key: 'at', header: t('audit.at'), render: (movement) => time(movement.at) },
  ];

  const countColumns: Column<model.DrawerCount>[] = [
    { key: 'counted', header: t('shift.counted'), align: 'end', render: (count) => money(count.countedMinor) },
    { key: 'expected', header: t('shift.expected'), align: 'end', render: (count) => money(count.expectedMinor) },
    {
      key: 'variance',
      header: t('shift.variance'),
      align: 'end',
      render: (count) => (
        <Badge tone={count.varianceMinor === 0 ? 'good' : 'warn'}>
          {model.formatVariance(count.varianceMinor)}
        </Badge>
      ),
    },
    { key: 'operator', header: t('shift.operator'), render: (count) => count.operator },
    { key: 'at', header: t('audit.at'), render: (count) => time(count.at) },
  ];

  return (
    <>
      <PageHeader
        eyebrow={config.tenant}
        title={t('shift.title')}
        description={t('shift.description')}
        actions={<OfflineBadge />}
      />
      {notice ? <InlineAlert tone="success">{notice}</InlineAlert> : null}
      {error ? <InlineAlert tone="error">{error}</InlineAlert> : null}

      <Card
        title={t('shift.current')}
        actions={
          isOpen ? (
            <Badge tone="good">{t('shift.openBadge')}</Badge>
          ) : (
            <Badge tone="warn">{t('shift.closedBadge')}</Badge>
          )
        }
      >
        <dl className="tb-kv">
          <dt>{t('shift.operator')}</dt>
          <dd>{shift.operator}</dd>
          <dt>{t('shift.openedAt')}</dt>
          <dd>{time(shift.openedAt)}</dd>
          <dt>{t('shift.float')}</dt>
          <dd>{money(shift.openingFloatMinor)}</dd>
          <dt>{t('shift.cashSales')}</dt>
          <dd>{money(cashSales)}</dd>
          <dt>{t('shift.cashRefunds')}</dt>
          <dd>{money(cashRefunds)}</dd>
          <dt>
            <strong>{t('shift.expected')}</strong>
          </dt>
          <dd>
            <strong>{money(expected)}</strong>
          </dd>
          {shift.closedAt !== undefined ? (
            <>
              <dt>{t('shift.closedAt')}</dt>
              <dd>{time(shift.closedAt)}</dd>
              <dt>{t('shift.closingVariance')}</dt>
              <dd>{model.formatVariance(shift.closingVarianceMinor ?? 0)}</dd>
            </>
          ) : null}
        </dl>
      </Card>

      {isOpen ? (
        <>
          <Card title={t('shift.movements')}>
            <div className="tb-form-grid">
              <SelectField
                label={t('shift.movement')}
                id={kindId}
                value={kind}
                onChange={(event) => setKind(event.target.value as model.MovementKind)}
              >
                <option value="cash-in">{t('shift.kind.cash-in')}</option>
                <option value="cash-out">{t('shift.kind.cash-out')}</option>
                <option value="safe-drop">{t('shift.kind.safe-drop')}</option>
              </SelectField>
              <Field label={t('shift.amount')} htmlFor={amountId}>
                <TextInput
                  id={amountId}
                  type="number"
                  inputMode="decimal"
                  step="0.01"
                  min="0"
                  value={amount}
                  onChange={(event) => setAmount(event.target.value)}
                />
              </Field>
              <div className="tb-form-actions">
                <Button
                  variant="secondary"
                  className="tb-touch"
                  onClick={() => {
                    const minor = parseMoneyMinor(amount);
                    if (minor === null) {
                      setError(t('terminal.required'));
                      return;
                    }
                    run(() => {
                      addMovement(kind, minor);
                      setAmount('');
                    }, t('shift.movementAdded'));
                  }}
                >
                  {t('shift.addMovement')}
                </Button>
              </div>
            </div>
            {shift.movements.length > 0 ? (
              <Table
                caption={t('shift.movements')}
                columns={movementColumns}
                rows={[...shift.movements].reverse()}
                rowKey={(movement) => movement.id}
              />
            ) : (
              <p className="tb-muted">{t('shift.noMovements')}</p>
            )}
          </Card>

          <Card title={t('shift.count')} description={t('shift.countHint')}>
            <div className="tb-form-grid">
              <Field label={t('shift.counted')} htmlFor={countedId}>
                <TextInput
                  id={countedId}
                  type="number"
                  inputMode="decimal"
                  step="0.01"
                  min="0"
                  value={counted}
                  onChange={(event) => setCounted(event.target.value)}
                />
              </Field>
              <div className="tb-form-actions">
                <Button
                  className="tb-touch"
                  onClick={() => {
                    if (countedMinor === null) {
                      setError(t('terminal.required'));
                      return;
                    }
                    run(() => {
                      closeShift(countedMinor);
                      setCounted('');
                    }, t('shift.closedNotice'));
                  }}
                >
                  {t('shift.closeShift')}
                </Button>
              </div>
            </div>
            {countedMinor !== null ? (
              <p className="tb-muted" aria-live="polite">
                {t('shift.variance')}: {model.formatVariance(countedMinor - expected)}
              </p>
            ) : null}
            {lastCount ? <p className="tb-muted">{t('shift.lastCount', { amount: money(lastCount.countedMinor) })}</p> : null}
          </Card>

          {shift.counts.length > 0 ? (
            <Card title={t('shift.counts')}>
              <Table
                caption={t('shift.counts')}
                columns={countColumns}
                rows={shift.counts}
                rowKey={(count) => count.id}
              />
            </Card>
          ) : null}
        </>
      ) : (
        <Card title={t('shift.closed')} description={t('shift.closedHint')}>
          {shift.counts.length > 0 ? (
            <Table
              caption={t('shift.counts')}
              columns={countColumns}
              rows={shift.counts}
              rowKey={(count) => count.id}
            />
          ) : null}
        </Card>
      )}
    </>
  );
}
