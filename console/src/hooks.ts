// SPDX-License-Identifier: Apache-2.0
import { useCallback, useEffect, useMemo, useState } from 'react';
import { ConsoleApi } from './api';
import { useSession } from './session';

export function useApi(): ConsoleApi {
  const { config } = useSession();
  return useMemo(
    () => new ConsoleApi({ baseUrl: config.baseUrl, token: config.token }),
    [config.baseUrl, config.token],
  );
}

type LoadState<T> = {
  data: T | undefined;
  loading: boolean;
  error: unknown;
  reload: () => void;
};

/** Race-safe loader keyed by explicit dependencies plus a manual reload counter. */
export function useLoader<T>(
  loader: () => Promise<T>,
  dependencies: readonly unknown[],
): LoadState<T> {
  const [data, setData] = useState<T>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [version, setVersion] = useState(0);
  const reload = useCallback(() => setVersion((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(undefined);
    loader()
      .then((value) => {
        if (!active) return;
        setData(value);
        setLoading(false);
      })
      .catch((reason: unknown) => {
        if (!active) return;
        setError(reason);
        setLoading(false);
      });
    return () => {
      active = false;
    };
    // The loader closes over exactly these dependencies.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, version]);

  return { data, loading, error, reload };
}
