// SPDX-License-Identifier: Apache-2.0
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { loadConfig, saveConfig, type ConsoleConfig } from './config';

type SessionValue = {
  config: ConsoleConfig;
  update: (patch: Partial<ConsoleConfig>) => void;
  signOut: () => void;
};

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<ConsoleConfig>(() => loadConfig());

  const update = useCallback((patch: Partial<ConsoleConfig>) => {
    setConfig((current) => {
      const next = { ...current, ...patch };
      saveConfig(next);
      return next;
    });
  }, []);

  const signOut = useCallback(() => {
    update({ token: '' });
  }, [update]);

  const value = useMemo(
    () => ({ config, update, signOut }),
    [config, update, signOut],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error('useSession must be used inside SessionProvider');
  return value;
}
