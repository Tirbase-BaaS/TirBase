// SPDX-License-Identifier: Apache-2.0
import { useId, useState, type FormEvent } from 'react';
import {
  Button,
  Card,
  ErrorState,
  Field,
  PageHeader,
  TextInput,
} from '@tirbase/console-design-system';
import { ConsoleApi, errorMessage } from './api';
import { useI18n } from './i18n';
import { useSession } from './session';

export function Login() {
  const { config, update } = useSession();
  const { t } = useI18n();
  const ids = {
    baseUrl: useId(),
    token: useId(),
    tenant: useId(),
  };
  const [baseUrl, setBaseUrl] = useState(config.baseUrl);
  const [tenant, setTenant] = useState(config.tenant);
  const [token, setToken] = useState(config.token);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token.trim()) {
      setError(t('auth.tokenRequired'));
      return;
    }
    setBusy(true);
    setError(undefined);
    const next = {
      ...config,
      baseUrl: baseUrl.trim().replace(/\/$/, ''),
      token: token.trim(),
      tenant: tenant.trim() || 'default',
    };
    try {
      // Every screen reads through the OpenAPI surface; validating with the
      // venues list exercises auth, tenant scoping and the documented API.
      await new ConsoleApi(next).listVenues(next.tenant);
      update(next);
    } catch (reason) {
      setError(`${t('auth.failed')} ${errorMessage(reason)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="tb-login" id="main-content">
      <div className="tb-login__panel">
        <PageHeader
          eyebrow={t('app.name')}
          title={t('auth.title')}
          description={t('auth.description')}
        />
        <Card title={t('settings.connection')}>
          <form onSubmit={submit} className="tb-stack" noValidate>
            <Field
              label={t('auth.baseUrl')}
              htmlFor={ids.baseUrl}
              hint={t('auth.baseUrlHint')}
            >
              <TextInput
                id={ids.baseUrl}
                value={baseUrl}
                onChange={(event) => setBaseUrl(event.target.value)}
                placeholder="https://gateway.example:8443"
                autoComplete="url"
                hintId={`${ids.baseUrl}-hint`}
              />
            </Field>
            <Field label={t('header.tenant')} htmlFor={ids.tenant}>
              <TextInput
                id={ids.tenant}
                value={tenant}
                onChange={(event) => setTenant(event.target.value)}
                autoComplete="organization"
                required
              />
            </Field>
            <Field
              label={t('auth.token')}
              htmlFor={ids.token}
              hint={t('auth.tokenHint')}
            >
              <TextInput
                id={ids.token}
                type="password"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                autoComplete="off"
                required
                hintId={`${ids.token}-hint`}
              />
            </Field>
            {error ? (
              <ErrorState
                title={t('auth.failed')}
                message={error}
                action={
                  <Button variant="secondary" onClick={() => setError(undefined)}>
                    {t('common.retry')}
                  </Button>
                }
              />
            ) : null}
            <div>
              <Button type="submit" disabled={busy}>
                {busy ? t('auth.connecting') : t('auth.open')}
              </Button>
            </div>
          </form>
        </Card>
      </div>
    </main>
  );
}
