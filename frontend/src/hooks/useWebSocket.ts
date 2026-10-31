import { useEffect, useRef, useState } from 'react';
import { getToken } from '@/lib/api';
import type { WsEvent } from '@/types/contract';

type Handler = (ev: WsEvent) => void;

/**
 * Live WebSocket stream with auto-reconnect + exponential-ish backoff.
 * Falls back silently to REST polling intervals in pages when offline.
 */
export function useWebSocket(onEvent: Handler) {
  const [connected, setConnected] = useState(false);
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let closed = false;
    let timer: number | undefined;

    const connect = () => {
      const token = getToken();
      if (!token || closed) return;
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      // relative URL → vite proxy in dev, same-origin in prod
      ws = new WebSocket(`${proto}://${location.host}/api/ws?token=${encodeURIComponent(token)}`);
      ws.onopen = () => {
        setConnected(true);
        retry = 0;
      };
      ws.onmessage = (msg) => {
        try {
          const ev = JSON.parse(msg.data) as WsEvent;
          handlerRef.current(ev);
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!closed) {
          retry = Math.min(retry + 1, 6);
          timer = window.setTimeout(connect, 1000 * retry + 500);
        }
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    const ping = window.setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 25_000);

    return () => {
      closed = true;
      window.clearInterval(ping);
      if (timer) window.clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return { connected };
}
