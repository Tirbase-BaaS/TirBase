// SPDX-License-Identifier: Apache-2.0
import { useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  InlineAlert,
  PageHeader,
  SelectField,
  Spinner,
  Table,
  type Column,
} from '@tirbase/console-design-system';
import { errorMessage } from '../api';
import { AuditApi, type AuditEntry, type EsignSignature, type ReportKind, type ReportSummary } from '../audit';
import { formatDateTime, formatInteger } from '../format';
import { useLoader } from '../hooks';
import { useI18n } from '../i18n';
import { useSession } from '../session';

const kinds: ReportKind[] = [
  'excursion_history',
  'quarantine_aging',
  'disposition',
  'calibration_due',
  'lot_traceability',
  'export_verification',
];

export function AuditScreen() {
  const { config } = useSession();
  const { t, locale } = useI18n();
  const api = useMemo(
    () => new AuditApi({ baseUrl: config.baseUrl, token: config.token }),
    [config.baseUrl, config.token],
  );
  const [kind, setKind] = useState<ReportKind | ''>('');
  const [selectedId, setSelectedId] = useState<string>();
  const [chain, setChain] = useState<{ valid: boolean; entries: number; head_hash: string; reasons: string[] }>();
  const [chainError, setChainError] = useState<string>();
  const [busy, setBusy] = useState(false);

  const reports = useLoader(
    () => api.listReports(config.tenant, kind === '' ? undefined : kind),
    [api, config.tenant, kind],
  );
  const signatures = useLoader(
    () => (selectedId ? api.listSignatures(selectedId) : Promise.resolve([])),
    [api, selectedId],
  );
  const detail = useLoader(
    () => (selectedId ? api.getReport(selectedId) : Promise.resolve(undefined)),
    [api, selectedId],
  );
  const audit = useLoader(() => api.listAudit(50), [api]);

  const selected = reports.data?.find((report) => report.report_id === selectedId);
  const detailed = detail.data;
  const alcoaSatisfied = detailed?.alcoa_satisfied ?? selected?.alcoa_satisfied;
  const custodyCount = detailed?.sources.length ?? selected?.row_count ?? 0;

  async function verifyChain() {
    setBusy(true);
    setChainError(undefined);
    try {
      setChain(await api.verifyAuditChain());
    } catch (reason) {
      setChainError(errorMessage(reason));
    } finally {
      setBusy(false);
    }
  }

  const reportColumns: Column<ReportSummary>[] = [
    {
      key: 'id',
      header: t('common.id'),
      render: (report) => <code>{report.report_id}</code>,
    },
    {
      key: 'kind',
      header: t('audit.kind'),
      render: (report) => <Badge tone="neutral">{report.kind}</Badge>,
    },
    {
      key: 'generated',
      header: t('audit.generated'),
      render: (report) => formatDateTime(report.generated_est, locale, config.timezone),
    },
    {
      key: 'rows',
      header: t('audit.rows'),
      align: 'end',
      render: (report) => formatInteger(report.row_count, locale),
    },
    {
      key: 'alcoa',
      header: t('audit.alcoa'),
      render: (report) =>
        report.alcoa_satisfied ? (
          <Badge tone="good">{t('audit.satisfied')}</Badge>
        ) : (
          <Badge tone="warn">{t('audit.failing')}</Badge>
        ),
    },
    {
      key: 'view',
      header: t('common.actions'),
      render: (report) => (
        <Button
          variant="secondary"
          onClick={() => setSelectedId(report.report_id)}
          aria-pressed={selectedId === report.report_id}
        >
          {t('common.view')}
        </Button>
      ),
    },
  ];

  const signatureColumns: Column<EsignSignature>[] = [
    { key: 'signer', header: t('audit.signer'), render: (item) => item.signer_id },
    { key: 'reason', header: t('audit.reason'), render: (item) => item.reason },
    {
      key: 'signed',
      header: t('audit.signedAt'),
      render: (item) => formatDateTime(item.signed_est, locale, config.timezone),
    },
    {
      key: 'digest',
      header: t('audit.recordDigest'),
      render: (item) => <code>{item.record_sha256.slice(0, 16)}…</code>,
    },
  ];

  const auditColumns: Column<AuditEntry>[] = [
    { key: 'seq', header: '#', align: 'end', render: (entry) => String(entry.seq) },
    { key: 'action', header: t('audit.action'), render: (entry) => entry.action },
    { key: 'subject', header: t('audit.subject'), render: (entry) => <code>{entry.subject}</code> },
    { key: 'actor', header: t('audit.actor'), render: (entry) => entry.actor_did },
    {
      key: 'at',
      header: t('audit.at'),
      render: (entry) => formatDateTime(entry.at_est, locale, config.timezone),
    },
  ];

  return (
    <>
      <PageHeader title={t('audit.title')} description={t('audit.description')} />

      {chain ? (
        <InlineAlert tone={chain.valid ? 'success' : 'error'}>
          {chain.valid
            ? t('audit.chainValid', { entries: chain.entries })
            : `${t('audit.chainInvalid')}: ${chain.reasons.join('; ')}`}
        </InlineAlert>
      ) : null}
      {chainError ? <InlineAlert tone="error">{chainError}</InlineAlert> : null}

      <Card title={t('audit.chain')}>
        <p>{t('audit.chainDescription')}</p>
        <div className="tb-form-grid">
          <Button onClick={verifyChain} disabled={busy}>
            {busy ? t('common.loading') : t('audit.verifyChain')}
          </Button>
        </div>
      </Card>

      <Card title={t('audit.reports')}>
        <div className="tb-form-grid">
          <SelectField
            label={t('audit.kind')}
            id="audit-kind"
            value={kind}
            onChange={(event) => {
              setKind(event.target.value as ReportKind | '');
              setSelectedId(undefined);
            }}
          >
            <option value="">{t('audit.allKinds')}</option>
            {kinds.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </SelectField>
        </div>
        {reports.loading ? <Spinner label={t('common.loading')} /> : null}
        {reports.error ? (
          <ErrorState
            title={t('common.errorTitle')}
            message={errorMessage(reports.error)}
            action={<Button onClick={reports.reload}>{t('common.retry')}</Button>}
          />
        ) : null}
        {reports.data ? (
          <Table
            caption={t('audit.reports')}
            columns={reportColumns}
            rows={reports.data}
            rowKey={(report) => report.report_id}
            empty={<EmptyState title={t('audit.noReports')} description={t('audit.noReportsBody')} />}
          />
        ) : null}
      </Card>

      {selectedId ? (
        <Card title={t('audit.detail')}>
          {selected ? (
            <>
              <p>
                <code>{selected.report_id}</code> · {selected.generated_by} ·{' '}
                {selected.content_sha256.slice(0, 16)}…
              </p>
              <p>
                {t('audit.alcoa')}:{' '}
                {alcoaSatisfied ? (
                  <Badge tone="good">{t('audit.satisfied')}</Badge>
                ) : (
                  <Badge tone="warn">{t('audit.failing')}</Badge>
                )}
              </p>
              <h3>{t('audit.signatures')}</h3>
              {signatures.loading ? <Spinner label={t('common.loading')} /> : null}
              {signatures.data ? (
                <Table
                  caption={t('audit.signatures')}
                  columns={signatureColumns}
                  rows={signatures.data}
                  rowKey={(item) => item.signature_id}
                  empty={
                    <EmptyState
                      title={t('audit.noSignatures')}
                      description={t('audit.noSignaturesBody')}
                    />
                  }
                />
              ) : null}
              <h3>{t('audit.custody')}</h3>
              <p>{t('audit.custodyBody', { count: custodyCount })}</p>
            </>
          ) : (
            <p>{t('audit.selectReport')}</p>
          )}
        </Card>
      ) : null}

      <Card title={t('audit.trail')}>
        {audit.loading ? <Spinner label={t('common.loading')} /> : null}
        {audit.error ? (
          <ErrorState
            title={t('common.errorTitle')}
            message={errorMessage(audit.error)}
            action={<Button onClick={audit.reload}>{t('common.retry')}</Button>}
          />
        ) : null}
        {audit.data ? (
          <Table
            caption={t('audit.trail')}
            columns={auditColumns}
            rows={audit.data}
            rowKey={(entry) => String(entry.seq)}
            empty={<EmptyState title={t('audit.noTrail')} description={t('audit.noTrailBody')} />}
          />
        ) : null}
      </Card>
    </>
  );
}
