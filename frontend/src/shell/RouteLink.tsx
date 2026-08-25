import type { MouseEvent, ReactNode } from "react";

import { isSafeApplicationPath } from "./routeRegistry";


export function RouteLink({
  children,
  className,
  current,
  label,
  onNavigate,
  path,
}: {
  readonly children: ReactNode;
  readonly className?: string;
  readonly current?: boolean;
  readonly label?: string;
  readonly onNavigate: (path: string) => boolean;
  readonly path: string;
}) {
  const safe = isSafeApplicationPath(path);
  const activate = (event: MouseEvent<HTMLAnchorElement>) => {
    if (!safe) {
      event.preventDefault();
      return;
    }
    if (
      event.button !== 0
      || event.metaKey
      || event.ctrlKey
      || event.shiftKey
      || event.altKey
    ) return;
    event.preventDefault();
    onNavigate(path);
  };
  return (
    <a
      aria-label={label}
      aria-current={current ? "page" : undefined}
      className={className}
      href={safe ? path : undefined}
      onClick={activate}
    >
      {children}
    </a>
  );
}
