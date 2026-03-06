import { useState, useEffect, useCallback } from 'react';

// ─── Generic data fetcher ─────────────────────────────────────────────────────
export function useAsync<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
) {
  const [data,    setData]    = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await fetcher());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => { run(); }, [run]);

  return { data, loading, error, refetch: run };
}

// ─── Polling variant ─────────────────────────────────────────────────────────
export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs = 30_000,
  deps: unknown[] = [],
) {
  const result = useAsync<T>(fetcher, deps);

  useEffect(() => {
    const id = setInterval(result.refetch, intervalMs);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, result.refetch]);

  return result;
}

// ─── Mutation hook ───────────────────────────────────────────────────────────
export function useMutation<TInput, TResult>(
  mutator: (input: TInput) => Promise<TResult>,
) {
  const [data,    setData]    = useState<TResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  const run = useCallback(async (input: TInput) => {
    setLoading(true);
    setError(null);
    try {
      const result = await mutator(input);
      setData(result);
      return result;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      throw e;
    } finally {
      setLoading(false);
    }
  }, [mutator]);

  const reset = useCallback(() => {
    setData(null);
    setError(null);
  }, []);

  return { data, loading, error, run, reset };
}
