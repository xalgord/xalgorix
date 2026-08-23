import type { ReactNode } from "react";
import { AlertCircle, Inbox } from "lucide-react";
import { cn } from "@/lib/utils";
import { useI18n } from "@/i18n";

export function EmptyState({
  title,
  description,
  icon,
  action,
  className,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 rounded-md border border-dashed border-border bg-card/50 p-10 text-center",
        className,
      )}
    >
      <div className="text-muted-foreground">{icon || <Inbox className="h-6 w-6" />}</div>
      <div>
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description && (
          <p className="mt-1 text-xs text-muted-foreground max-w-md">
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({
  title,
  description,
  action,
  className,
}: {
  title?: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  const { t } = useI18n();
  return (
    <div
      className={cn(
        "flex items-start gap-3 rounded-md border border-red-500/30 bg-red-500/5 p-4",
        className,
      )}
    >
      <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400 mt-0.5" />
      <div className="flex-1">
        <p className="text-sm font-medium text-red-700 dark:text-red-300">
          {title || t("common.somethingWrong")}
        </p>
        {description && (
          <p className="mt-1 text-xs text-red-700/70 dark:text-red-200/70">{description}</p>
        )}
        {action && <div className="mt-2">{action}</div>}
      </div>
    </div>
  );
}
