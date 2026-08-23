import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function MetricCard({
  label,
  value,
  hint,
  icon,
  to,
  className,
  accent,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  to?: string;
  className?: string;
  accent?: "default" | "critical" | "warning" | "success";
}) {
  const accentClass =
    accent === "critical"
      ? "text-red-600 dark:text-red-400"
      : accent === "warning"
        ? "text-amber-600 dark:text-amber-400"
        : accent === "success"
          ? "text-emerald-600 dark:text-emerald-400"
          : "text-foreground";

  const body = (
    <div
      className={cn(
        // h-full + flex column keeps every card in a row the same height,
        // even when some have a hint and others don't, and prevents the
        // 6-col grid from looking ragged when labels truncate differently.
        "group flex h-full flex-col rounded-md border border-border bg-card p-4 transition-colors card-hover",
        to && "cursor-pointer",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="truncate text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </p>
        {icon && <span className="shrink-0 text-muted-foreground">{icon}</span>}
      </div>
      <div
        className={cn(
          "mt-3 truncate text-3xl font-semibold leading-none tabular-nums",
          accentClass,
        )}
        title={typeof value === "string" || typeof value === "number" ? String(value) : undefined}
      >
        {value}
      </div>
      {hint != null && (
        <div className="mt-auto pt-2 text-xs text-muted-foreground truncate">
          {hint}
        </div>
      )}
    </div>
  );
  return to ? (
    <Link to={to} className="block focus:outline-none focus:ring-1 focus:ring-ring rounded-md">
      {body}
    </Link>
  ) : (
    body
  );
}
