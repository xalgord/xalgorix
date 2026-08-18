import { cn, normalizeSeverity, type Severity } from "@/lib/utils";
import { useI18n } from "@/i18n";

const STYLES: Record<Severity, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-neutral-500/10 text-neutral-400 border-neutral-500/30",
};

export function SeverityBadge({
  severity,
  className,
  showDot = true,
}: {
  severity?: string;
  className?: string;
  showDot?: boolean;
}) {
  const { t } = useI18n();
  const sev = normalizeSeverity(severity);
  const dotColor: Record<Severity, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-500",
    info: "bg-neutral-500",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        STYLES[sev],
        className,
      )}
    >
      {showDot && (
        <span
          className={cn("h-1.5 w-1.5 rounded-full", dotColor[sev])}
          aria-hidden
        />
      )}
      {t(`severity.${sev}`)}
    </span>
  );
}
