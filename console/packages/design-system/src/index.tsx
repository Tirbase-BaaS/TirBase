// SPDX-License-Identifier: Apache-2.0

// Shared design system for every operator console vertical. Screens must use
// these primitives so keyboard, focus and contrast behaviour stays identical.
import {
  forwardRef,
  useId,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
} from 'react';

export function Button({
  variant = 'primary',
  type = 'button',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'danger' | 'quiet';
}) {
  return (
    <button
      type={type}
      className={`tb-button tb-button--${variant} ${className}`.trim()}
      {...props}
    />
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="tb-page-header">
      <div>
        {eyebrow ? <p className="tb-eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {description ? <p className="tb-muted">{description}</p> : null}
      </div>
      {actions ? <div className="tb-page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function Card({
  title,
  description,
  actions,
  children,
  as: Tag = 'section',
}: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  as?: 'section' | 'div';
}) {
  const headingId = useId();
  return (
    <Tag className="tb-card" aria-labelledby={title ? headingId : undefined}>
      {title || actions ? (
        <div className="tb-card__header">
          <div>
            {title ? <h2 id={headingId}>{title}</h2> : null}
            {description ? <p className="tb-muted">{description}</p> : null}
          </div>
          {actions ? <div className="tb-card__actions">{actions}</div> : null}
        </div>
      ) : null}
      <div className="tb-card__body">{children}</div>
    </Tag>
  );
}

export function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div className={`tb-field${error ? ' tb-field--error' : ''}`}>
      <label htmlFor={htmlFor}>{label}</label>
      {children}
      {hint ? (
        <p className="tb-hint" id={`${htmlFor}-hint`}>
          {hint}
        </p>
      ) : null}
      {error ? (
        <p className="tb-field__error" id={`${htmlFor}-error`} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export const TextInput = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean; hintId?: string }
>(function TextInput({ invalid, hintId, className = '', ...props }, ref) {
  return (
    <input
      ref={ref}
      className={`tb-input ${className}`.trim()}
      aria-invalid={invalid || undefined}
      aria-describedby={hintId}
      {...props}
    />
  );
});

export function SelectField({
  label,
  id,
  hint,
  error,
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & {
  label: string;
  id: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <Field label={label} htmlFor={id} hint={hint} error={error}>
      <select
        id={id}
        className="tb-input tb-select"
        aria-describedby={hint ? `${id}-hint` : undefined}
        {...props}
      >
        {children}
      </select>
    </Field>
  );
}

export type Column<T> = {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  align?: 'start' | 'end';
};

export function Table<T>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
}: {
  caption: string;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  empty?: ReactNode;
}) {
  if (rows.length === 0 && empty) return <>{empty}</>;
  return (
    <div className="tb-table-wrap" tabIndex={0} role="region" aria-label={caption}>
      <table className="tb-table">
        <caption className="tb-visually-hidden">{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                className={column.align === 'end' ? 'tb-table__end' : undefined}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)}>{columns.map((column) => (
              <td
                key={column.key}
                className={column.align === 'end' ? 'tb-table__end' : undefined}
              >
                {column.render(row)}
              </td>
            ))}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="tb-state tb-state--empty">
      <span className="tb-state__mark" aria-hidden="true">◇</span>
      <div>
        <h3>{title}</h3>
        <p>{description}</p>
        {action}
      </div>
    </div>
  );
}

export function ErrorState({
  title,
  message,
  action,
}: {
  title: string;
  message: string;
  action?: ReactNode;
}) {
  return (
    <div className="tb-state tb-state--error" role="alert">
      <span className="tb-state__mark" aria-hidden="true">!</span>
      <div>
        <h3>{title}</h3>
        <p>{message}</p>
        {action}
      </div>
    </div>
  );
}

export function Spinner({ label }: { label: string }) {
  return (
    <div className="tb-spinner" role="status" aria-live="polite">
      <span className="tb-spinner__dot" aria-hidden="true" />
      {label}
    </div>
  );
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'good' | 'warn' }) {
  return <span className={`tb-badge tb-badge--${tone}`}>{children}</span>;
}

export function VisuallyHidden({ children }: { children: ReactNode }) {
  return <span className="tb-visually-hidden">{children}</span>;
}

export function InlineAlert({ tone = 'info', children }: { tone?: 'info' | 'success' | 'error'; children: ReactNode }) {
  return (
    <div className={`tb-alert tb-alert--${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  );
}
