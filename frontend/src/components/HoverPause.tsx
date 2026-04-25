import { useEffect, useRef, useSyncExternalStore } from "react";

let pauseCount = 0;
const listeners = new Set<() => void>();

function notify() { for (const l of listeners) l(); }
function subscribe(l: () => void) { listeners.add(l); return () => { listeners.delete(l); }; }
function getSnapshot() { return pauseCount; }

export function pause()  { pauseCount += 1; notify(); }
export function resume() { if (pauseCount > 0) { pauseCount -= 1; notify(); } }

export function usePaused(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot) > 0;
}

const LEAVE_GRACE_MS = 120;

export function HoverPause(
  { children, className, style }:
  { children: React.ReactNode; className?: string; style?: React.CSSProperties },
) {
  const active = useRef(false);
  const leaveTimer = useRef<number | null>(null);

  useEffect(() => () => {
    if (active.current) { resume(); active.current = false; }
    if (leaveTimer.current != null) window.clearTimeout(leaveTimer.current);
  }, []);

  const onEnter = () => {
    if (leaveTimer.current != null) {
      window.clearTimeout(leaveTimer.current);
      leaveTimer.current = null;
    }
    if (!active.current) { pause(); active.current = true; }
  };

  const onLeave = () => {
    if (leaveTimer.current != null) window.clearTimeout(leaveTimer.current);
    leaveTimer.current = window.setTimeout(() => {
      if (active.current) { resume(); active.current = false; }
      leaveTimer.current = null;
    }, LEAVE_GRACE_MS);
  };

  return (
    <span className={className} style={style}
          onMouseEnter={onEnter} onMouseLeave={onLeave}>
      {children}
    </span>
  );
}
