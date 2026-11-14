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
  Spinner,
  Table,
  TextInput,
  type Column,
} from '@tirbase/console-design-system';
import { errorMessage, type Gate, type Venue } from '../api';
import { formatDateTime, formatInteger } from '../format';
import { useApi, useLoader } from '../hooks';
import { useI18n } from '../i18n';
import { useSession } from '../session';

export function VenueScreen() {
  const { config } = useSession();
  const api = useApi();
  const { t, locale } = useI18n();
  const nameId = useId();
  const capacityId = useId();
  const filterId = useId();
  const gateId = useId();
  const nameInput = useRef<HTMLInputElement>(null);

  const venues = useLoader(() => api.listVenues(config.tenant), [api, config.tenant]);
  const [filter, setFilter] = useState('');
  const [selectedId, setSelectedId] = useState<string>();
  const [name, setName] = useState('');
  const [capacity, setCapacity] = useState('');
  const [gateName, setGateName] = useState('');
  const [formError, setFormError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setSelectedId(undefined);
    setNotice(undefined);
  }, [config.tenant]);

  const gates = useLoader(
    () =>
      selectedId
        ? api.listGates(config.tenant, selectedId)
        : Promise.resolve(undefined),
    [api, config.tenant, selectedId],
  );

  const allVenues = venues.data?.items ?? [];
  const selected = allVenues.find((venue) => venue.id === selectedId);
  const visibleVenues = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return allVenues;
    return allVenues.filter(
      (venue) =>
        venue.data.name.toLowerCase().includes(needle) ||
        venue.id.toLowerCase().includes(needle),
    );
  }, [allVenues, filter]);

  async function createVenue(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) {
      setFormError(t('common.required'));
      nameInput.current?.focus();
      return;
    }
    setBusy(true);
    setFormError(undefined);
    try {
      const venue = await api.createVenue(config.tenant, {
        name: name.trim(),
        capacity: capacity ? Number(capacity) : undefined,
      });
      setName('');
      setCapacity('');
      setNotice(t('venues.created'));
      setSelectedId(venue.id);
      venues.reload();
    } catch (reason) {
      setFormError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  async function createGate(event: FormEvent) {
    event.preventDefault();
    if (!selectedId) return;
    if (!gateName.trim()) {
      setFormError(t('common.required'));
      return;
    }
    setBusy(true);
    setFormError(undefined);
    try {
      await api.createGate(config.tenant, selectedId, gateName.trim());
      setGateName('');
      setNotice(t('venues.gateCreated'));
      gates.reload();
    } catch (reason) {
      setFormError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  const columns: Column<Venue>[] = [
    {
      key: 'name',
      header: t('common.name'),
      render: (venue) => <strong>{venue.data.name}</strong>,
    },
    {
      key: 'capacity',
      header: t('venues.capacity'),
      align: 'end',
      render: (venue) =>
        venue.data.capacity === undefined
          ? '—'
          : formatInteger(venue.data.capacity, locale),
    },
    {
      key: 'updated',
      header: t('common.updated'),
      render: (venue) => formatDateTime(venue.updated_est, locale, config.timezone),
    },
    {
      key: 'id',
      header: t('common.id'),
      render: (venue) => <code>{venue.id}</code>,
    },
    {
      key: 'actions',
      header: t('common.actions'),
      align: 'end',
      render: (venue) => (
        <Button
          variant="quiet"
          aria-pressed={venue.id === selectedId}
          onClick={() => setSelectedId(venue.id)}
        >
          {t('common.view')}
        </Button>
      ),
    },
  ];

  const gateColumns: Column<Gate>[] = [
    { key: 'name', header: t('common.name'), render: (gate) => gate.data.name },
    {
      key: 'created',
      header: t('common.created'),
      render: (gate) => formatDateTime(gate.created_est, locale, config.timezone),
    },
    { key: 'id', header: t('common.id'), render: (gate) => <code>{gate.id}</code> },
  ];

  return (
    <>
      <PageHeader
        eyebrow={config.tenant}
        title={t('venues.title')}
        description={t('venues.description')}
        actions={<Badge>{t('venues.venues')}</Badge>}
      />
      {notice ? <InlineAlert tone="success">{notice}</InlineAlert> : null}
      <Card title={t('venues.newVenue')} description={t('venues.venuesDescription')}>
        <form className="tb-form-grid" onSubmit={createVenue} noValidate>
          <Field label={t('venues.name')} htmlFor={nameId} error={formError}>
            <TextInput
              id={nameId}
              ref={nameInput}
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              invalid={Boolean(formError)}
            />
          </Field>
          <Field label={t('venues.capacity')} htmlFor={capacityId}>
            <TextInput
              id={capacityId}
              type="number"
              min="0"
              step="1"
              value={capacity}
              onChange={(event) => setCapacity(event.target.value)}
            />
          </Field>
          <div className="tb-form-actions">
            <Button type="submit" disabled={busy}>{t('venues.create')}</Button>
          </div>
        </form>
      </Card>

      <Card title={t('venues.venues')}>
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
          <Button variant="secondary" onClick={venues.reload}>{t('common.retry')}</Button>
        </div>
        {venues.loading ? <Spinner label={t('common.loading')} /> : null}
        {venues.error ? (
          <ErrorState
            title={t('common.errorTitle')}
            message={errorMessage(venues.error)}
            action={<Button onClick={venues.reload}>{t('common.retry')}</Button>}
          />
        ) : null}
        {!venues.loading && !venues.error ? (
          <Table
            caption={t('venues.venues')}
            columns={columns}
            rows={visibleVenues}
            rowKey={(venue) => venue.id}
            empty={
              <EmptyState
                title={filter ? t('common.filter') : t('venues.noVenues')}
                description={filter ? t('common.filterHint') : t('venues.noVenuesBody')}
                action={
                  !filter ? (
                    <Button variant="secondary" onClick={() => nameInput.current?.focus()}>
                      {t('venues.newVenue')}
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
          title={t('venues.gatesFor', { venue: selected.data.name })}
          actions={<code>{selected.id}</code>}
        >
          {gates.loading ? <Spinner label={t('common.loading')} /> : null}
          {gates.error ? (
            <ErrorState
              title={t('common.errorTitle')}
              message={errorMessage(gates.error)}
              action={<Button onClick={gates.reload}>{t('common.retry')}</Button>}
            />
          ) : null}
          {!gates.loading && !gates.error ? (
            <Table
              caption={t('venues.gates')}
              columns={gateColumns}
              rows={gates.data?.items ?? []}
              rowKey={(gate) => gate.id}
              empty={
                <EmptyState title={t('venues.noGates')} description={t('venues.noGatesBody')} />
              }
            />
          ) : null}
          <form className="tb-form-grid" onSubmit={createGate} noValidate>
            <Field label={t('venues.gateName')} htmlFor={gateId}>
              <TextInput
                id={gateId}
                value={gateName}
                onChange={(event) => setGateName(event.target.value)}
                required
              />
            </Field>
            <div className="tb-form-actions">
              <Button type="submit" disabled={busy}>{t('venues.addGate')}</Button>
            </div>
          </form>
        </Card>
      ) : null}
    </>
  );
}
