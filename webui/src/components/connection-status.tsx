import { useWSStore } from "@/store/ws";
import { cn } from "@/lib/utils";

const STATUS_LABEL: Record<string, string> = {
  idle: "Idle",
  connecting: "Connecting",
  connected: "Connected",
  disconnected: "Disconnected",
  reconnecting: "Reconnecting",
};

const STATUS_COLOR: Record<string, string> = {
  idle: "bg-neutral-500",
  connecting: "bg-amber-500",
  connected: "bg-emerald-500",
  disconnected: "bg-red-500",
  reconnecting: "bg-amber-500",
};

export function ConnectionStatus({ compact }: { compact?: boolean }) {
  const status = useWSStore((s) => s.status);
  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 rounded-md border border-border bg-card px-2 py-1 text-xs",
        compact && "py-0.5",
      )}
      title={`WebSocket: ${STATUS_LABEL[status] || status}`}
    >
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          STATUS_COLOR[status] || "bg-neutral-500",
          status === "connecting" || status === "reconnecting" ? "pulse-dot" : "",
        )}
      />
      <span className="text-muted-foreground">{STATUS_LABEL[status] || status}</span>
    </div>
  );
}

export function ConnectionBanner() {
  const status = useWSStore((s) => s.status);
  const err = useWSStore((s) => s.lastError);
  if (status === "connected" || status === "idle" || status === "connecting") {
    return null;
  }
  return (
    <div className="border-b border-amber-500/30 bg-amber-500/10 px-6 py-2 text-xs text-amber-700 dark:text-amber-200">
      WebSocket {status === "reconnecting" ? "reconnecting" : "disconnected"}
      {err ? ` — ${err}` : ". Live updates are paused."}
    </div>
  );
}
