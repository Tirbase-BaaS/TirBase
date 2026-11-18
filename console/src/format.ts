// SPDX-License-Identifier: Apache-2.0
import type { Locale } from './i18n';

export function formatDateTime(
  epochSeconds: number,
  locale: Locale,
  timeZone: string,
): string {
  if (!Number.isFinite(epochSeconds)) return '—';
  try {
    return new Intl.DateTimeFormat(locale, {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone,
    }).format(new Date(epochSeconds * 1000));
  } catch {
    return new Date(epochSeconds * 1000).toISOString();
  }
}

export function formatMoney(
  minor: number,
  currency: string,
  locale: Locale,
): string {
  try {
    return new Intl.NumberFormat(locale, {
      style: 'currency',
      currency: currency.toUpperCase(),
    }).format(minor / 100);
  } catch {
    return `${(minor / 100).toFixed(2)} ${currency.toUpperCase()}`;
  }
}

/**
 * Parse a decimal money entry such as `12.50` into integer minor units.
 * Returns `null` for anything that is not a plain non-negative amount with at
 * most two decimals, so a stray keystroke cannot become a charge.
 */
export function parseMoneyMinor(text: string): number | null {
  const normalised = text.trim().replace(',', '.');
  if (!/^\d+(\.\d{0,2})?$/.test(normalised)) return null;
  const [whole = '0', fraction = ''] = normalised.split('.');
  return Number(whole) * 100 + Number(`${fraction}00`.slice(0, 2));
}

export function formatTemperature(milli: number, locale: Locale): string {
  return new Intl.NumberFormat(locale, {
    minimumFractionDigits: 1,
    maximumFractionDigits: 3,
  }).format(milli / 1000) + ' °C';
}

export function formatInteger(value: number, locale: Locale): string {
  return new Intl.NumberFormat(locale).format(value);
}
