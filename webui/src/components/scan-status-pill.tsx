import { cn } from "@/lib/utils";
import { useI18n } from "@/i18n";

const STYLES: Record<string, { className: string; label: string }> = {
  running: {
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    label: "Running",
  },
  pending: {
    className: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    label: "Pending",
  },
  paused: {
    className: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    label: "Paused",
  },
  saved: {
    className: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    label: "Saved",
  },
  finished: {
    className: "bg-neutral-500/10 text-neutral-300 border-neutral-500/30",
    label: "Completed",
  },
  completed: {
    className: "bg-neutral-500/10 text-neutral-300 border-neutral-500/30",
    label: "Completed",
  },
  stopped: {
    className: "bg-red-500/10 text-red-400 border-red-500/30",
    label: "Stopped",
  },
  failed: {
    className: "bg-red-500/10 text-red-400 border-red-500/30",
    label: "Failed",
  },
};

export function ScanStatusPill({
  status,
  className,
}: {
  status?: string;
  className?: string;
}) {
  const { t } = useI18n();
  const key = (status || "").toLowerCase();
  const meta = STYLES[key] || {
    className: "bg-neutral-500/10 text-neutral-300 border-neutral-500/30",
    label: status || "Unknown",
  };
  // Localize known statuses; fall back to the built-in English label.
  const localizedLabel = STYLES[key] ? t(`status.${key}`) : meta.label;
  const dotPulse =
    key === "running" || key === "pending" ? "pulse-dot" : "";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        meta.className,
        className,
      )}
    >
      <span
        className={cn("h-1.5 w-1.5 rounded-full bg-current", dotPulse)}
        aria-hidden
      />
      {localizedLabel}
    </span>
  );
}
