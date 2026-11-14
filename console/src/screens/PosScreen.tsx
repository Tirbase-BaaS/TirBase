// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from 'react';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  InlineAlert,
  PageHeader,
  SelectField,
  Spinner,
  Table,
  TextInput,
  type Column,
} from '@tirbase/console-design-system';
import { errorMessage, type Order, type OrderLine } from '../api';
import { formatDateTime, formatInteger, formatMoney } from '../format';
import { useApi, useLoader } from '../hooks';
import { useI18n } from '../i18n';
import { useSession } from '../session';

const currencies = ['EUR', 'USD', 'GBP'];

export function PosScreen() {
  const { config } = useSession();
  const api = useApi();
  const { t, locale } = useI18n();
  const totalId = useId();
  const currencyId = useId();
  const filterId = useId();
  const skuId = useId();
  const qtyId = useId();
  const priceId = useId();
  const totalInput = useRef<HTMLInputElement>(null);

  const orders = useLoader(() => api.listOrders(config.tenant), [api, config.tenant]);
  const [filter, setFilter] = useState('');
  const [selectedId, setSelectedId] = useState<string>();
  const [currency, setCurrency] = useState('EUR');
  const [total, setTotal] = useState('');
  const [sku, setSku] = useState('');
  const [quantity, setQuantity] = useState('1');
  const [price, setPrice] = useState('');
  const [formError, setFormError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setSelectedId(undefined);
    setNotice(undefined);
  }, [config.tenant]);

  const lines = useLoader(
    () =>
      selectedId
        ? api.listLines(config.tenant, selectedId)
        : Promise.resolve(undefined),
    [api, config.tenant, selectedId],
  );

  const allOrders = orders.data?.items ?? [];
  const selected = allOrders.find((order) => order.id === selectedId);
  const visibleOrders = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return allOrders;
    return allOrders.filter(
      (order) =>
        order.id.toLowerCase().includes(needle) ||
        (order.data.status ?? '').toLowerCase().includes(needle) ||
        String(order.data.total_minor).includes(needle),
    );
  }, [allOrders, filter]);

  async function createOrder(event: FormEvent) {
    event.preventDefault();
    const amount = Number(total);
    if (!Number.isFinite(amount) || amount < 0) {
      setFormError(t('common.required'));
      totalInput.current?.focus();
      return;
    }
    setBusy(true);
    setFormError(undefined);
    try {
      const order = await api.createOrder(config.tenant, currency, Math.round(amount * 100));
      setTotal('');
      setNotice(t('pos.orderCreated'));
      setSelectedId(order.id);
      orders.reload();
    } catch (reason) {
      setFormError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  async function createLine(event: FormEvent) {
    event.preventDefault();
    if (!selectedId) return;
    const parsedQuantity = Number(quantity);
    const parsedPrice = Number(price);
    if (!sku.trim() || !Number.isFinite(parsedQuantity) || !Number.isFinite(parsedPrice)) {
      setFormError(t('common.required'));
      return;
    }
    setBusy(true);
    setFormError(undefined);
    try {
      await api.createLine(config.tenant, selectedId, {
        sku: sku.trim(),
        quantity: Math.trunc(parsedQuantity),
        unit_price_minor: Math.round(parsedPrice * 100),
      });
      setSku('');
      setQuantity('1');
      setPrice('');
      setNotice(t('pos.lineCreated'));
      lines.reload();
    } catch (reason) {
      setFormError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  const columns: Column<Order>[] = [
    {
      key: 'total',
      header: t('pos.total'),
      align: 'end',
      render: (order) => (
        <strong>{formatMoney(order.data.total_minor, order.data.currency, locale)}</strong>
      ),
    },
    {
      key: 'status',
      header: t('pos.status'),
      render: (order) => (
        <Badge tone={order.data.status === 'paid' ? 'good' : 'neutral'}>
          {order.data.status ?? 'open'}
        </Badge>
      ),
    },
    {
      key: 'created',
      header: t('common.created'),
      render: (order) => formatDateTime(order.created_est, locale, config.timezone),
    },
    {
      key: 'id',
      header: t('common.id'),
      render: (order) => <code>{order.id}</code>,
    },
    {
      key: 'actions',
      header: t('common.actions'),
      align: 'end',
      render: (order) => (
        <Button
          variant="quiet"
          aria-pressed={order.id === selectedId}
          onClick={() => setSelectedId(order.id)}
        >
          {t('common.view')}
        </Button>
      ),
    },
  ];

  const lineColumns: Column<OrderLine>[] = [
    { key: 'sku', header: t('pos.sku'), render: (line) => line.data.sku },
    {
      key: 'quantity',
      header: t('pos.quantity'),
      align: 'end',
      render: (line) => formatInteger(line.data.quantity, locale),
    },
    {
      key: 'price',
      header: t('pos.unitPrice'),
      align: 'end',
      render: (line) =>
        formatMoney(line.data.unit_price_minor, selected?.data.currency ?? 'EUR', locale),
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow={config.tenant}
        title={t('pos.title')}
        description={t('pos.description')}
        actions={<Badge>{t('pos.orders')}</Badge>}
      />
      {notice ? <InlineAlert tone="success">{notice}</InlineAlert> : null}
      <Card title={t('pos.newOrder')} description={t('pos.ordersDescription')}>
        <form className="tb-form-grid" onSubmit={createOrder} noValidate>
          <SelectField
            label={t('pos.currency')}
            id={currencyId}
            value={currency}
            onChange={(event) => setCurrency(event.target.value)}
          >
            {currencies.map((code) => <option key={code} value={code}>{code}</option>)}
          </SelectField>
          <Field label={t('pos.total')} htmlFor={totalId} error={formError}>
            <TextInput
              id={totalId}
              ref={totalInput}
              type="number"
              inputMode="decimal"
              min="0"
              step="0.01"
              value={total}
              onChange={(event) => setTotal(event.target.value)}
              required
              invalid={Boolean(formError)}
            />
          </Field>
          <div className="tb-form-actions">
            <Button type="submit" disabled={busy}>{t('pos.createOrder')}</Button>
          </div>
        </form>
      </Card>

      <Card title={t('pos.orders')}>
        <div className="tb-filters">
          <Field label={t('common.filter')} htmlFor={filterId} hint={t('common.filterHint')}>
            <TextInput
              id={filterId}
              type="search"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              hintId={`${filterId}-hint`}
            />
          </Field>
          <Button variant="secondary" onClick={orders.reload}>{t('common.retry')}</Button>
        </div>
        {orders.loading ? <Spinner label={t('common.loading')} /> : null}
        {orders.error ? (
          <ErrorState
            title={t('common.errorTitle')}
            message={errorMessage(orders.error)}
            action={<Button onClick={orders.reload}>{t('common.retry')}</Button>}
          />
        ) : null}
        {!orders.loading && !orders.error ? (
          <Table
            caption={t('pos.orders')}
            columns={columns}
            rows={visibleOrders}
            rowKey={(order) => order.id}
            empty={
              <EmptyState
                title={filter ? t('common.filter') : t('pos.noOrders')}
                description={filter ? t('common.filterHint') : t('pos.noOrdersBody')}
                action={
                  !filter ? (
                    <Button variant="secondary" onClick={() => totalInput.current?.focus()}>
                      {t('pos.newOrder')}
                    </Button>
                  ) : (
                    <Button variant="secondary" onClick={() => setFilter('')}>
                      {t('common.cancel')}
                    </Button>
                  )
                }
              />
            }
          />
        ) : null}
      </Card>

      {selected ? (
        <Card
          title={t('pos.linesFor', { order: selected.id })}
          actions={<Badge>{formatMoney(selected.data.total_minor, selected.data.currency, locale)}</Badge>}
        >
          {lines.loading ? <Spinner label={t('common.loading')} /> : null}
          {lines.error ? (
            <ErrorState
              title={t('common.errorTitle')}
              message={errorMessage(lines.error)}
              action={<Button onClick={lines.reload}>{t('common.retry')}</Button>}
            />
          ) : null}
          {!lines.loading && !lines.error ? (
            <Table
              caption={t('pos.lines')}
              columns={lineColumns}
              rows={lines.data?.items ?? []}
              rowKey={(line) => line.id}
              empty={
                <EmptyState title={t('pos.noLines')} description={t('pos.noLinesBody')} />
              }
            />
          ) : null}
          <form className="tb-form-grid" onSubmit={createLine} noValidate>
            <Field label={t('pos.sku')} htmlFor={skuId}>
              <TextInput id={skuId} value={sku} onChange={(event) => setSku(event.target.value)} required />
            </Field>
            <Field label={t('pos.quantity')} htmlFor={qtyId}>
              <TextInput
                id={qtyId}
                type="number"
                min="1"
                step="1"
                value={quantity}
                onChange={(event) => setQuantity(event.target.value)}
                required
              />
            </Field>
            <Field label={t('pos.unitPrice')} htmlFor={priceId}>
              <TextInput
                id={priceId}
                type="number"
                min="0"
                step="0.01"
                value={price}
                onChange={(event) => setPrice(event.target.value)}
                required
              />
            </Field>
            <div className="tb-form-actions">
              <Button type="submit" disabled={busy}>{t('pos.addLine')}</Button>
            </div>
          </form>
        </Card>
      ) : null}
    </>
  );
}
