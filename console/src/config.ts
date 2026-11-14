// SPDX-License-Identifier: Apache-2.0
import type { Locale } from './i18n';

export type ConsoleConfig = {
  baseUrl: string;
  token: string;
  tenant: string;
  timezone: string;
  locale: Locale;
};

const STORAGE_KEY = 'tirbase.console.config.v1';

export function defaultTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

export function loadConfig(): ConsoleConfig {
  const fallback: ConsoleConfig = {
    baseUrl: '',
    token: '',
    tenant: 'default',
    timezone: defaultTimezone(),
    locale: 'en',
  };
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as Partial<ConsoleConfig>;
    return {
      baseUrl: typeof parsed.baseUrl === 'string' ? parsed.baseUrl : fallback.baseUrl,
      token: typeof parsed.token === 'string' ? parsed.token : fallback.token,
      tenant:
        typeof parsed.tenant === 'string' && parsed.tenant
          ? parsed.tenant
          : fallback.tenant,
      timezone:
        typeof parsed.timezone === 'string' && parsed.timezone
          ? parsed.timezone
          : fallback.timezone,
      locale: parsed.locale === 'es' ? 'es' : 'en',
    };
  } catch {
    return fallback;
  }
}

export function saveConfig(config: ConsoleConfig): void {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
}

export function timezoneOptions(current: string): string[] {
  let zones: string[] = [];
  try {
    const supported = (
      Intl as typeof Intl & { supportedValuesOf?: (key: string) => string[] }
    ).supportedValuesOf;
    zones = supported ? supported('timeZone') : [];
  } catch {
    zones = [];
  }
  if (!zones.includes('UTC')) zones.unshift('UTC');
  if (current && !zones.includes(current)) zones.unshift(current);
  return zones;
}
