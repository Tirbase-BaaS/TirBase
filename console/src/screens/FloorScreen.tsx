// SPDX-License-Identifier: Apache-2.0
import { Badge, Card, PageHeader } from '@tirbase/console-design-system';
import { formatMoney } from '../format';
import { useI18n } from '../i18n';
import { useSession } from '../session';
import * as model from '../pos/model';
import { usePos } from '../pos/store';
import { OfflineBadge } from '../pos/ui';

export function FloorScreen() {
  const { t, locale } = useI18n();
  const { config } = useSession();
  const { state } = usePos();

  return (
    <>
      <PageHeader
        eyebrow={config.tenant}
        title={t('floor.title')}
        description={t('floor.description')}
        actions={<OfflineBadge />}
      />
      <Card title={t('floor.tables')} description={t('floor.legend')}>
        <div className="tb-floor-grid">
          {model.TABLES.map((id) => {
            const checks = state.checks.filter(
              (check) => check.tableId === id && check.status !== 'voided',
            );
            const open = checks.filter((check) => check.status === 'open');
            const total = checks.reduce(
              (sum, check) => sum + model.computeTotals(check).totalMinor,
              0,
            );
            const label = id === 'counter' ? t('terminal.counter') : id.toUpperCase();
            return (
              <section
                key={id}
                className={`tb-floor-table${open.length > 0 ? ' tb-floor-table--busy' : ''}`}
                aria-label={label}
              >
                <div className="tb-floor-table__head">
                  <h2>{label}</h2>
                  {open.length > 0 ? (
                    <Badge tone="warn">{t('floor.occupied', { count: open.length })}</Badge>
                  ) : (
                    <Badge tone="good">{t('floor.free')}</Badge>
                  )}
                </div>
                <p className="tb-floor-table__total">{formatMoney(total, state.currency, locale)}</p>
                <ul className="tb-floor-table__checks">
                  {checks.slice(0, 3).map((check) => (
                    <li key={check.id}>
                      #{check.number} · {t(`terminal.status.${check.status}`)} ·{' '}
                      {formatMoney(model.computeTotals(check).totalMinor, state.currency, locale)}
                    </li>
                  ))}
                  {checks.length === 0 ? <li>{t('floor.noChecks')}</li> : null}
                </ul>
                <a
                  className="tb-button tb-button--secondary tb-touch"
                  href={`#/terminal?table=${id}`}
                >
                  {t('floor.openTable')}
                </a>
              </section>
            );
          })}
        </div>
      </Card>
    </>
  );
}
