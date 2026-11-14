// SPDX-License-Identifier: Apache-2.0
import { useId, useState, type FormEvent } from 'react';
import {
  Button,
  Card,
  Field,
  InlineAlert,
  PageHeader,
  SelectField,
  TextInput,
} from '@tirbase/console-design-system';
import { defaultTimezone, timezoneOptions } from '../config';
import { locales, useI18n, type Locale } from '../i18n';
import { useSession } from '../session';

export function SettingsScreen() {
  const { config, update } = useSession();
  const { t } = useI18n();
  const baseUrlId = useId();
  const tokenId = useId();
  const tenantId = useId();
  const timezoneId = useId();
  const localeId = useId();
  const [saved, setSaved] = useState(false);
  const [baseUrl, setBaseUrl] = useState(config.baseUrl);
  const [token, setToken] = useState(config.token);
  const [tenant, setTenant] = useState(config.tenant);
  const [timezone, setTimezone] = useState(config.timezone);
  const [locale, setLocale] = useState<Locale>(config.locale);

  function submit(event: FormEvent) {
    event.preventDefault();
    update({
      baseUrl: baseUrl.trim().replace(/\/$/, ''),
      token: token.trim(),
      tenant: tenant.trim() || 'default',
      timezone: timezone || defaultTimezone(),
      locale,
    });
    setSaved(true);
  }

  return (
    <>
      <PageHeader title={t('settings.title')} description={t('settings.description')} />
      {saved ? <InlineAlert tone="success">{t('settings.saved')}</InlineAlert> : null}
      <form onSubmit={submit}>
        <Card title={t('settings.connection')}>
          <div className="tb-form-grid">
            <Field label={t('auth.baseUrl')} htmlFor={baseUrlId} hint={t('auth.baseUrlHint')}>
              <TextInput
                id={baseUrlId}
                value={baseUrl}
                onChange={(event) => setBaseUrl(event.target.value)}
                hintId={`${baseUrlId}-hint`}
              />
            </Field>
            <Field label={t('header.tenant')} htmlFor={tenantId}>
              <TextInput
                id={tenantId}
                value={tenant}
                onChange={(event) => setTenant(event.target.value)}
                required
              />
            </Field>
            <Field label={t('auth.token')} htmlFor={tokenId} hint={t('settings.tokenNote')}>
              <TextInput
                id={tokenId}
                type="password"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                hintId={`${tokenId}-hint`}
              />
            </Field>
          </div>
        </Card>
        <Card title={t('settings.preferences')}>
          <div className="tb-form-grid">
            <SelectField
              label={t('header.timezone')}
              id={timezoneId}
              value={timezone}
              onChange={(event) => setTimezone(event.target.value)}
            >
              {timezoneOptions(timezone).map((zone) => (
                <option key={zone} value={zone}>{zone}</option>
              ))}
            </SelectField>
            <SelectField
              label={t('header.language')}
              id={localeId}
              value={locale}
              onChange={(event) => setLocale(event.target.value as Locale)}
            >
              {locales.map((item) => (
                <option key={item.value} value={item.value}>{item.label}</option>
              ))}
            </SelectField>
          </div>
        </Card>
        <Button type="submit">{t('settings.save')}</Button>
      </form>
    </>
  );
}
