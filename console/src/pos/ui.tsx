// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useRef } from 'react';
import { Badge, Button } from '@tirbase/console-design-system';
import { useI18n } from '../i18n';
import { usePos } from './store';

/** Connection, work-offline switch and the pending-sync count. */
export function OfflineBadge() {
  const { t } = useI18n();
  const { linkUp, forcedOffline, setForcedOffline, state } = usePos();
  const pending = state.queue.length;
  return (
    <div className="tb-pos-status">
      <Badge tone={linkUp ? 'good' : 'warn'}>
        {linkUp ? t('terminal.online') : t('terminal.offline')}
      </Badge>
      {pending > 0 ? (
        <span className="tb-pos-status__pending" role="status">
          {t('terminal.pendingSync', { count: pending })}
        </span>
      ) : null}
      <Button
        variant="secondary"
        className="tb-touch"
        aria-pressed={forcedOffline}
        onClick={() => setForcedOffline(!forcedOffline)}
      >
        {forcedOffline ? t('terminal.workOnline') : t('terminal.workOffline')}
      </Button>
    </div>
  );
}

export function TableLabel({ id }: { id: string }) {
  const { t } = useI18n();
  return <>{id === 'counter' ? t('terminal.counter') : id.toUpperCase()}</>;
}

/**
 * A short single-field prompt rendered next to the action that raised it.
 *
 * It is a labelled form, not a modal dialog, so focus order and the surrounding
 * content stay reachable; Escape cancels and the field takes focus on open.
 */
export function Prompt({
  title,
  label,
  defaultValue = '',
  confirmLabel,
  kind = 'text',
  onConfirm,
  onCancel,
}: {
  title: string;
  label: string;
  defaultValue?: string;
  confirmLabel: string;
  kind?: 'text' | 'number';
  onConfirm: (value: string) => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  return (
    <form
      className="tb-prompt"
      onSubmit={(event) => {
        event.preventDefault();
        onConfirm(inputRef.current?.value ?? '');
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          onCancel();
        }
      }}
    >
      <h3>{title}</h3>
      <label className="tb-field" htmlFor={inputId}>
        <span>{label}</span>
        <input
          id={inputId}
          ref={inputRef}
          className="tb-input"
          type={kind === 'number' ? 'number' : 'text'}
          inputMode={kind === 'number' ? 'decimal' : undefined}
          step={kind === 'number' ? '0.01' : undefined}
          min={kind === 'number' ? '0' : undefined}
          defaultValue={defaultValue}
        />
      </label>
      <div className="tb-inline">
        <Button type="submit">{confirmLabel}</Button>
        <Button type="button" variant="secondary" onClick={onCancel}>
          {t('common.cancel')}
        </Button>
      </div>
    </form>
  );
}

/** Prompts for the unresolved settlement/table conflicts. */
export function ConflictPanel() {
  const { t } = useI18n();
  const { state, resolveConflict } = usePos();
  if (state.conflicts.length === 0) return null;
  return (
    <section className="tb-conflict" role="alert" aria-labelledby="tb-conflict-title">
      <h2 id="tb-conflict-title">{t('terminal.conflict')}</h2>
      <ul>
        {state.conflicts.map((conflict) => (
          <li key={conflict.id}>
            <p>
              {conflict.kind === 'table-occupied'
                ? t('terminal.conflictTable', {
                    table: conflict.tableId.toUpperCase(),
                    number: conflict.occupantNumber,
                  })
                : t('terminal.conflictSale', { message: conflict.message })}
            </p>
            <div className="tb-inline">
              {conflict.kind === 'table-occupied' ? (
                <>
                  <Button
                    className="tb-touch"
                    onClick={() => resolveConflict(conflict.id, 'move-anyway')}
                  >
                    {t('terminal.moveAnyway')}
                  </Button>
                  <Button
                    variant="secondary"
                    className="tb-touch"
                    onClick={() => resolveConflict(conflict.id, 'cancel')}
                  >
                    {t('common.cancel')}
                  </Button>
                </>
              ) : (
                <>
                  <Button
                    className="tb-touch"
                    onClick={() => resolveConflict(conflict.id, 'retry')}
                  >
                    {t('terminal.retry')}
                  </Button>
                  <Button
                    variant="secondary"
                    className="tb-touch"
                    onClick={() => resolveConflict(conflict.id, 'discard')}
                  >
                    {t('terminal.discard')}
                  </Button>
                </>
              )}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
