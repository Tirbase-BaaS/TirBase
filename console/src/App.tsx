// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useMemo, useState } from 'react';
import { Button } from '@tirbase/console-design-system';
import { I18nContext, locales, translate, useI18n, type Locale, type MessageKey } from './i18n';
import { timezoneOptions } from './config';
import { useSession } from './session';
import { Login } from './Login';
import { ColdChainScreen } from './screens/ColdChainScreen';
import { PosScreen } from './screens/PosScreen';
import { TerminalScreen } from './screens/TerminalScreen';
import { FloorScreen } from './screens/FloorScreen';
import { KdsScreen } from './screens/KdsScreen';
import { ShiftScreen } from './screens/ShiftScreen';
import { VenueScreen } from './screens/VenueScreen';
import { SettingsScreen } from './screens/SettingsScreen';
import { AuditScreen } from './screens/AuditScreen';

type Route =
  | 'cold-chain'
  | 'pos'
  | 'terminal'
  | 'floor'
  | 'kds'
  | 'shift'
  | 'venues'
  | 'audit'
  | 'settings';

const routes: { id: Route; key: MessageKey }[] = [
  { id: 'cold-chain', key: 'nav.coldChain' },
  { id: 'pos', key: 'nav.pos' },
  { id: 'terminal', key: 'nav.terminal' },
  { id: 'floor', key: 'nav.floor' },
  { id: 'kds', key: 'nav.kds' },
  { id: 'shift', key: 'nav.shift' },
  { id: 'venues', key: 'nav.venues' },
  { id: 'audit', key: 'nav.audit' },
  { id: 'settings', key: 'nav.settings' },
];

type Location = { route: Route; params: URLSearchParams };

function readLocation(): Location {
  const raw = window.location.hash.replace(/^#\/?/, '');
  const [path = '', query = ''] = raw.split('?');
  const route = routes.some((candidate) => candidate.id === path)
    ? (path as Route)
    : 'cold-chain';
  return { route, params: new URLSearchParams(query) };
}

function useHashLocation(): Location {
  const [location, setLocation] = useState<Location>(readLocation);
  useEffect(() => {
    const onChange = () => setLocation(readLocation());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return location;
}

function TenantSwitcher() {
  const { config, update } = useSession();
  const { t } = useI18n();
  const id = useId();
  const [value, setValue] = useState(config.tenant);
  useEffect(() => setValue(config.tenant), [config.tenant]);

  const commit = () => {
    const tenant = value.trim() || 'default';
    if (tenant !== config.tenant) update({ tenant });
  };

  return (
    <div className="tb-control">
      <label htmlFor={id}>{t('header.tenant')}</label>
      <input
        id={id}
        className="tb-control__input"
        list="tb-tenants"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => {
          if (event.key === 'Enter') {
            event.preventDefault();
            commit();
          }
        }}
      />
      <datalist id="tb-tenants">
        <option value="default" />
        <option value="acme" />
        <option value="northwind" />
      </datalist>
    </div>
  );
}

export function App() {
  const { config, update, signOut } = useSession();
  const location = useHashLocation();
  const route = location.route;
  const t = useMemo(
    () => (key: MessageKey, vars?: Record<string, string | number>) =>
      translate(config.locale, key, vars),
    [config.locale],
  );
  const timezoneId = useId();
  const localeId = useId();
  const timezones = useMemo(() => timezoneOptions(config.timezone), [config.timezone]);

  // Move keyboard focus into the content after sign-in and route changes so
  // the skip link and tab order stay predictable.
  useEffect(() => {
    if (config.token) document.getElementById('main-content')?.focus();
  }, [route, config.token]);

  if (!config.token) {
    return (
      <I18nContext.Provider value={{ locale: config.locale, t }}>
        <Login />
      </I18nContext.Provider>
    );
  }

  return (
    <I18nContext.Provider value={{ locale: config.locale, t }}>
      <a className="tb-skip-link" href="#main-content">
        {t('app.skip')}
      </a>
      <div className="tb-shell">
        <header className="tb-topbar">
          <div className="tb-brand">
            <span className="tb-brand__mark" aria-hidden="true">T</span>
            <div>
              <strong>{t('app.name')}</strong>
              <span>{t('app.console')}</span>
            </div>
          </div>
          <div className="tb-topbar__controls">
            <TenantSwitcher />
            <div className="tb-control">
              <label htmlFor={timezoneId}>{t('header.timezone')}</label>
              <select
                id={timezoneId}
                className="tb-control__input"
                value={config.timezone}
                onChange={(event) => update({ timezone: event.target.value })}
              >
                {timezones.map((zone) => (
                  <option key={zone} value={zone}>{zone}</option>
                ))}
              </select>
            </div>
            <div className="tb-control">
              <label htmlFor={localeId}>{t('header.language')}</label>
              <select
                id={localeId}
                className="tb-control__input"
                value={config.locale}
                onChange={(event) => update({ locale: event.target.value as Locale })}
              >
                {locales.map((locale) => (
                  <option key={locale.value} value={locale.value}>{locale.label}</option>
                ))}
              </select>
            </div>
            <Button variant="secondary" onClick={signOut}>{t('header.signOut')}</Button>
          </div>
        </header>

        <div className="tb-body">
          <nav className="tb-nav" aria-label={t('nav.label')}>
            <ul>
              {routes.map((item) => (
                <li key={item.id}>
                  <a
                    href={`#/${item.id}`}
                    aria-current={route === item.id ? 'page' : undefined}
                  >
                    {t(item.key)}
                  </a>
                </li>
              ))}
            </ul>
            <p className="tb-nav__tenant" aria-live="polite">
              {t('header.tenant')}: <strong>{config.tenant}</strong>
            </p>
          </nav>
          <main id="main-content" tabIndex={-1} className="tb-content">
            {route === 'cold-chain' ? <ColdChainScreen /> : null}
            {route === 'pos' ? <PosScreen /> : null}
            {route === 'terminal' ? (
              <TerminalScreen tableParam={location.params.get('table') ?? undefined} />
            ) : null}
            {route === 'floor' ? <FloorScreen /> : null}
            {route === 'kds' ? <KdsScreen /> : null}
            {route === 'shift' ? <ShiftScreen /> : null}
            {route === 'venues' ? <VenueScreen /> : null}
            {route === 'audit' ? <AuditScreen /> : null}
            {route === 'settings' ? <SettingsScreen /> : null}
          </main>
        </div>
      </div>
    </I18nContext.Provider>
  );
}
