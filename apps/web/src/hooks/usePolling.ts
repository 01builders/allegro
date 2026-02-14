import { useEffect, useState, useRef, useCallback } from "react";
import { config } from "@/config";
import type { ChainHead, TxStatus } from "@/api/types";
import { getChainHead, getTxStatus } from "@/api/client";

export function useChainHead(pollMs = config.pollMs) {
  const [head, setHead] = useState<ChainHead | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const tick = async () => {
      try {
        const data = await getChainHead();
        if (active) {
          setHead(data);
          setError(null);
        }
      } catch (err) {
        if (active) setError((err as Error).message);
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), pollMs);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [pollMs]);

  return { head, error };
}

export function useTxStatus(txHash: string | null, pollMs = config.pollMs) {
  const [status, setStatus] = useState<TxStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const stoppedRef = useRef(false);

  const reset = useCallback(() => {
    setStatus(null);
    setError(null);
    stoppedRef.current = false;
  }, []);

  useEffect(() => {
    stoppedRef.current = false;

    if (!txHash) {
      setStatus(null);
      return;
    }

    let active = true;
    const tick = async () => {
      if (stoppedRef.current) return;
      try {
        const data = await getTxStatus(txHash);
        if (active) {
          setStatus(data);
          setError(null);
          if (data.qc_formed) {
            stoppedRef.current = true;
          }
        }
      } catch (err) {
        if (active) setError((err as Error).message);
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), pollMs);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [txHash, pollMs]);

  return { status, error, reset };
}
