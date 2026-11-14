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
import { errorMessage, type Reading, type Site } from '../api';
import { formatDateTime, formatTemperature } from '../format';
import { useApi, useLoader } from '../hooks';
import { useI18n } from '../i18n';
import { useSession } from '../session';

export function ColdChainScreen() {
  const { config } = useSession();
  const api = useApi();
  const { t, locale } = useI18n();
  const nameId = useId();
  const filterId = useId();
  const tempId = useId();
  const nameInput = useRef<HTMLInputElement>(null);

  const sites = useLoader(() => api.listSites(config.tenant), [api, config.tenant]);
  const [filter, setFilter] = useState('');
  const [selectedId, setSelectedId] = useState<string>();
  const [name, setName] = useState('');
  const [temperature, setTemperature] = useState('');
  const [formError, setFormError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setSelectedId(undefined);
    setNotice(undefined);
  }, [config.tenant]);

  const readings = useLoader(
    () =>
      selectedId
        ? api.listReadings(config.tenant, selectedId)
        : Promise.resolve(undefined),
    [api, config.tenant, selectedId],
  );

  const allSites = sites.data?.items ?? [];
  const selected = allSites.find((site) => site.id === selectedId);
  const visibleSites = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return allSites;
    return allSites.filter(
      (site) =>
        site.data.name.toLowerCase().includes(needle) ||
        site.id.toLowerCase().includes(needle),
    );
  }, [allSites, filter]);

  async function createSite(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) {
      setFormError(t('common.required'));
      nameInput.current?.focus();
      return;
    }
    setBusy(true);
    setFormError(undefined);
    try {
      const site = await api.createSite(config.tenant, name.trim());
      setName('');
      setNotice(t('cold.created'));
      setSelectedId(site.id);
      sites.reload();
    } catch (reason) {
      setFormError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  async function createReading(event: FormEvent) {
    event.preventDefault();
    if (!selectedId) return;
    const parsed = Number(temperature);
    if (!Number.isFinite(parsed)) {
      setFormError(t('common.required'));
      return;
    }
    setBusy(true);
    setFormError(undefined);
    try {
      await api.createReading(config.tenant, selectedId, Math.round(parsed * 1000));
      setTemperature('');
      setNotice(t('cold.readingCreated'));
      readings.reload();
    } catch (reason) {
      setFormError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  const columns: Column<Site>[] = [
    {
      key: 'name',
      header: t('common.name'),
      render: (site) => <strong>{site.data.name}</strong>,
    },
    {
      key: 'id',
      header: t('common.id'),
      render: (site) => <code>{site.id}</code>,
    },
    {
      key: 'updated',
      header: t('common.updated'),
      render: (site) => formatDateTime(site.updated_est, locale, config.timezone),
    },
    {
      key: 'actions',
      header: t('common.actions'),
      align: 'end',
      render: (site) => (
        <Button
          variant="quiet"
          aria-pressed={site.id === selectedId}
          onClick={() => setSelectedId(site.id)}
        >
          {t('cold.select')}
        </Button>
      ),
    },
  ];

  const readingColumns: Column<Reading>[] = [
    {
      key: 'temperature',
      header: t('cold.temperatureColumn'),
      render: (reading) => formatTemperature(reading.data.celsius_milli, locale),
    },
    {
      key: 'recorded',
      header: t('cold.recorded'),
      render: (reading) =>
        formatDateTime(reading.data.recorded_est ?? reading.created_est, locale, config.timezone),
    },
    {
      key: 'id',
      header: t('common.id'),
      render: (reading) => <code>{reading.id}</code>,
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow={config.tenant}
        title={t('cold.title')}
        description={t('cold.description')}
        actions={<Badge tone="good">{formatDateTime(Date.now() / 1000, locale, config.timezone)}</Badge>}
      />
      {notice ? <InlineAlert tone="success">{notice}</InlineAlert> : null}
      <Card
        title={t('cold.newSite')}
        description={t('cold.sitesDescription')}
      >
        <form className="tb-form-grid" onSubmit={createSite} noValidate>
          <Field label={t('cold.siteName')} htmlFor={nameId} error={formError}>
            <TextInput
              id={nameId}
              ref={nameInput}
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              invalid={Boolean(formError)}
            />
          </Field>
          <div className="tb-form-actions">
            <Button type="submit" disabled={busy}>{t('cold.createSite')}</Button>
          </div>
        </form>
      </Card>

      <Card title={t('cold.sites')}>
        <div className="tb-filters">
          <Field label={t('common.filter')} htmlFor={filterId} hint={t('common.filterHint')}>
            <TextInput
              id={filterId}
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              type="search"
              hintId={`${filterId}-hint`}
            />
          </Field>
          <Button variant="secondary" onClick={sites.reload}>{t('common.retry')}</Button>
        </div>
        {sites.loading ? <Spinner label={t('common.loading')} /> : null}
        {sites.error ? (
          <ErrorState
            title={t('common.errorTitle')}
            message={`${errorMessage(sites.error)} ${t('common.offlineHint')}`}
            action={<Button onClick={sites.reload}>{t('common.retry')}</Button>}
          />
        ) : null}
        {!sites.loading && !sites.error ? (
          <Table
            caption={t('cold.sites')}
            columns={columns}
            rows={visibleSites}
            rowKey={(site) => site.id}
            empty={
              <EmptyState
                title={filter ? t('common.filter') : t('cold.noSites')}
                description={filter ? t('common.filterHint') : t('cold.noSitesBody')}
                action={
                  !filter ? (
                    <Button variant="secondary" onClick={() => nameInput.current?.focus()}>
                      {t('cold.newSite')}
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
          title={t('cold.readingsFor', { site: selected.data.name })}
          actions={<code>{selected.id}</code>}
        >
          {readings.loading ? <Spinner label={t('common.loading')} /> : null}
          {readings.error ? (
            <ErrorState
              title={t('common.errorTitle')}
              message={errorMessage(readings.error)}
              action={<Button onClick={readings.reload}>{t('common.retry')}</Button>}
            />
          ) : null}
          {!readings.loading && !readings.error ? (
            <Table
              caption={t('cold.readings')}
              columns={readingColumns}
              rows={readings.data?.items ?? []}
              rowKey={(reading) => reading.id}
              empty={
                <EmptyState
                  title={t('cold.noReadings')}
                  description={t('cold.noReadingsBody')}
                />
              }
            />
          ) : null}
          <form className="tb-form-grid" onSubmit={createReading} noValidate>
            <Field label={t('cold.temperature')} htmlFor={tempId}>
              <TextInput
                id={tempId}
                type="number"
                inputMode="decimal"
                step="0.001"
                value={temperature}
                onChange={(event) => setTemperature(event.target.value)}
                required
              />
            </Field>
            <div className="tb-form-actions">
              <Button type="submit" disabled={busy}>{t('cold.addReading')}</Button>
            </div>
          </form>
        </Card>
      ) : null}
    </>
  );
}
