import { useState, useEffect, useRef, useCallback } from "react";

/**
 * useWebSocket — Real-time alert subscription hook.
 *
 * Connects to the SOC WebSocket endpoint and receives live alert updates.
 * Auto-reconnects on disconnect with exponential backoff.
 *
 * Usage:
 *   const { messages, connected, send } = useWebSocket("ws://localhost:8000/ws/alerts");
 */
export default function useWebSocket(url) {
  const [messages, setMessages] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const reconnectTimeout = useRef(null);
  const retryCount = useRef(0);
  const maxRetries = 10;

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        retryCount.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setMessages(prev => [data, ...prev].slice(0, 100)); // Keep last 100
        } catch (e) {
          console.warn("WebSocket message parse error:", e);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        // Auto-reconnect with exponential backoff
        if (retryCount.current < maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, retryCount.current), 30000);
          retryCount.current += 1;
          reconnectTimeout.current = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch (e) {
      setConnected(false);
    }
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);
    };
  }, [connect]);

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof data === "string" ? data : JSON.stringify(data));
    }
  }, []);

  return { messages, connected, send };
}
