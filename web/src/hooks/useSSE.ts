import { useState, useEffect, useRef, useCallback } from 'react';
import { createEventStream } from '@/lib/api';
import type { Threat, ExplanationEvent } from '@/types';

export type SSEStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

export interface SSEState {
  threats:    Threat[];
  status:     SSEStatus;
  lastPing:   Date | null;
  totalSeen:  number;
}

export function useSSE(maxThreats = 200) {
  const [state, setState] = useState<SSEState>({
    threats:   [],
    status:    'disconnected',
    lastPing:  null,
    totalSeen: 0,
  });
  const esRef = useRef<EventSource | null>(null);

  const connect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
    }
    setState(s => ({ ...s, status: 'connecting' }));

    const es = createEventStream();
    esRef.current = es;

    es.onopen = () =>
      setState(s => ({ ...s, status: 'connected' }));

    // New threat detected during an active scan.
    es.addEventListener('threat', (e: MessageEvent) => {
      try {
        const threat = JSON.parse(e.data) as Threat;
        setState(s => ({
          ...s,
          threats:   [threat, ...s.threats].slice(0, maxThreats),
          totalSeen: s.totalSeen + 1,
        }));
      } catch { /* ignore parse error */ }
    });

    // AI explanation arrived (async — may come seconds after the threat event).
    es.addEventListener('explanation', (e: MessageEvent) => {
      try {
        const payload = JSON.parse(e.data) as ExplanationEvent;
        setState(s => ({
          ...s,
          threats: s.threats.map(t =>
            // Match by threat_id (exact) or package+type fallback.
            (t.id === payload.threat_id ||
              (t.package === payload.package && t.type === payload.type))
              ? { ...t, explanation: payload.explanation }
              : t,
          ),
        }));
      } catch { /* ignore parse error */ }
    });

    es.addEventListener('ping', () =>
      setState(s => ({ ...s, lastPing: new Date(), status: 'connected' })),
    );

    // "done" means scanning finished; keep connection open for explanation events.
    es.addEventListener('done', () =>
      setState(s => ({ ...s, status: 'connected' })),
    );

    es.onerror = () => {
      setState(s => ({ ...s, status: 'error' }));
      es.close();
      // Auto-reconnect after 5 s
      setTimeout(connect, 5_000);
    };
  }, [maxThreats]);

  const disconnect = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
    setState(s => ({ ...s, status: 'disconnected' }));
  }, []);

  const clearThreats = useCallback(() =>
    setState(s => ({ ...s, threats: [], totalSeen: 0 })),
  []);

  // Auto-connect on mount
  useEffect(() => {
    connect();
    return disconnect;
  }, [connect, disconnect]);

  return { ...state, connect, disconnect, clearThreats };
}
