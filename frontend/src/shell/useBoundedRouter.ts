import { useCallback, useEffect, useMemo, useState } from "react";

import { isSafeApplicationPath, routeForPath, type ApplicationRoute } from "./routeRegistry";


export type BoundedRouter = {
  readonly path: string;
  readonly route: ApplicationRoute | null;
  readonly navigate: (path: string) => boolean;
};

export function useBoundedRouter(): BoundedRouter {
  const [path, setPath] = useState(() => window.location.pathname);

  useEffect(() => {
    const onPopState = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback((destination: string) => {
    // CRITICAL: navigation accepts only exact closed-registry paths; arbitrary URLs never reach history.
    if (!isSafeApplicationPath(destination)) return false;
    if (window.location.pathname !== destination) window.history.pushState({}, "", destination);
    setPath(destination);
    return true;
  }, []);

  return useMemo(() => ({ path, route: routeForPath(path), navigate }), [navigate, path]);
}
