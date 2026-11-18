// SPDX-License-Identifier: Apache-2.0
import { useState } from 'react';
import {
  Badge,
  Button,
  EmptyState,
  PageHeader,
} from '@tirbase/console-design-system';
import { formatDateTime } from '../format';
import { useI18n } from '../i18n';
import { useSession } from '../session';
import * as model from '../pos/model';
import { usePos } from '../pos/store';
import { OfflineBadge, TableLabel } from '../pos/ui';

const columns: { status: model.TicketStatus; key: 'queued' | 'ready' | 'served' }[] = [
  { status: 'queued', key: 'queued' },
  { status: 'ready', key: 'ready' },
  { status: 'served', key: 'served' },
];

export function KdsScreen() {
  const { t, locale } = useI18n();
  const { config } = useSession();
  const { state, bumpTicket, bumpItem, recallTicket } = usePos();
  const [station, setStation] = useState<'all' | model.Station>('all');

  const stations: ('all' | model.Station)[] = ['all', ...model.STATIONS];
  const visible = state.tickets.filter(
    (ticket) => station === 'all' || ticket.station === station,
  );

  return (
    <>
      <PageHeader
        eyebrow={config.tenant}
        title={t('kds.title')}
        description={t('kds.description')}
        actions={<OfflineBadge />}
      />

      <div className="tb-inline tb-inline--wrap" role="group" aria-label={t('kds.station')}>
        {stations.map((value) => (
          <Button
            key={value}
            variant={station === value ? 'primary' : 'secondary'}
            className="tb-touch"
            aria-pressed={station === value}
            onClick={() => setStation(value)}
          >
            {value === 'all' ? t('kds.all') : t(`station.${value}`)}
          </Button>
        ))}
      </div>

      {state.tickets.length === 0 ? (
        <EmptyState title={t('kds.noTickets')} description={t('kds.noTicketsBody')} />
      ) : (
        <div className="tb-kds-board">
          {columns.map((column) => {
            const tickets = visible.filter((ticket) => ticket.status === column.status);
            return (
              <section
                key={column.status}
                className="tb-kds-column"
                aria-labelledby={`kds-${column.status}`}
              >
                <h2 id={`kds-${column.status}`}>
                  {t(`kds.${column.key}`)} <Badge>{tickets.length}</Badge>
                </h2>
                {tickets.length === 0 ? (
                  <p className="tb-muted">{t('kds.empty')}</p>
                ) : (
                  tickets.map((ticket) => (
                    <article
                      key={ticket.id}
                      className={`tb-kds-ticket tb-kds-ticket--${ticket.status}`}
                      aria-labelledby={`ticket-${ticket.id}`}
                    >
                      <header className="tb-kds-ticket__head">
                        <h3 id={`ticket-${ticket.id}`}>
                          #{ticket.number} · {t(`station.${ticket.station}`)}
                        </h3>
                        <p className="tb-muted">
                          <TableLabel id={ticket.tableId} /> ·{' '}
                          {formatDateTime(ticket.createdAt / 1000, locale, config.timezone)}
                        </p>
                        {ticket.recallCount > 0 ? (
                          <Badge tone="warn">
                            {t('kds.recalled', { count: ticket.recallCount })}
                          </Badge>
                        ) : null}
                      </header>
                      <ul className="tb-kds-items">
                        {ticket.items.map((item) => (
                          <li key={item.id}>
                            <span>
                              {item.quantity} × {item.name}
                            </span>
                            {item.status === 'ready' ? (
                              <Badge tone="good">{t('kds.itemReady')}</Badge>
                            ) : (
                              <Button
                                variant="secondary"
                                className="tb-touch"
                                onClick={() => bumpItem(ticket.id, item.id)}
                              >
                                {t('kds.bumpItem')}
                              </Button>
                            )}
                          </li>
                        ))}
                      </ul>
                      <div className="tb-kds-ticket__actions">
                        {ticket.status === 'served' ? (
                          <Button
                            className="tb-touch tb-touch--wide"
                            onClick={() => recallTicket(ticket.id)}
                          >
                            {t('kds.recall')}
                          </Button>
                        ) : (
                          <Button
                            className="tb-touch tb-touch--wide"
                            onClick={() => bumpTicket(ticket.id)}
                          >
                            {t('kds.bump')}
                          </Button>
                        )}
                      </div>
                    </article>
                  ))
                )}
              </section>
            );
          })}
        </div>
      )}
    </>
  );
}
