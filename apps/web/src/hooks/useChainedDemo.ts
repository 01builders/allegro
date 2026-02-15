import { useCallback, useEffect, useRef, useState } from "react";
import { startChainedDemo } from "@/api/client";
import type { DemoState } from "@/api/types";

const INITIAL_STATE: DemoState = {
  status: "idle",
  steps: [],
  chainHead: null,
  done: null,
  error: null,
};

export function useChainedDemo() {
  const [state, setState] = useState<DemoState>(INITIAL_STATE);
  const controllerRef = useRef<AbortController | null>(null);

  const start = useCallback(() => {
    // Abort any in-flight demo
    controllerRef.current?.abort();

    setState({ ...INITIAL_STATE, status: "running" });

    const controller = startChainedDemo({
      onStep: (event) => {
        setState((prev) => ({
          ...prev,
          steps: [...prev.steps, event],
        }));
      },
      onChainHead: (event) => {
        setState((prev) => ({
          ...prev,
          chainHead: event,
        }));
      },
      onDone: (event) => {
        setState((prev) => ({
          ...prev,
          status: "done",
          done: event,
        }));
      },
      onError: (event) => {
        setState((prev) => ({
          ...prev,
          status: "error",
          error: event.message,
        }));
      },
    });

    controllerRef.current = controller;
  }, []);

  const reset = useCallback(() => {
    controllerRef.current?.abort();
    controllerRef.current = null;
    setState(INITIAL_STATE);
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      controllerRef.current?.abort();
    };
  }, []);

  return { state, start, reset };
}
