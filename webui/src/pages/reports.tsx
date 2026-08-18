import { Link } from "react-router-dom";
import { useMemo, useState } from "react";
import { Download, ExternalLink, FileText, Search, Trash2 } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/states";
import { useDeleteScan, useScansList } from "@/api/queries";
import { timeAgo } from "@/lib/utils";
import { useI18n } from "@/i18n";

export default function ReportsPage() {
  const { t } = useI18n();
  const { data: scans, isLoading } = useScansList();
  const del = useDeleteScan();
  const [query, setQuery] = useState("");

  const list = useMemo(() => {
    const q = query.toLowerCase();
    return (scans ?? [])
      .filter((s) =>
        !q ? true : s.target.toLowerCase().includes(q) || s.id.toLowerCase().includes(q),
      )
      .sort((a, b) =>
        new Date(b.started_at).getTime() - new Date(a.started_at).getTime(),
      );
  }, [scans, query]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("reports.title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("reports.subtitle")}</p>
      </div>

      <Card>
        <CardContent className="p-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t("reports.searchPlaceholder")}
              className="pl-8"
            />
          </div>
        </CardContent>
      </Card>

      <Card className="overflow-hidden">
        {isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-14 w-full" />
            ))}
          </div>
        ) : list.length === 0 ? (
          <EmptyState
            icon={<FileText className="h-6 w-6" />}
            title={t("reports.emptyTitle")}
            description={t("reports.emptyDescription")}
          />
        ) : (
          <ul className="divide-y divide-border">
            {list.map((s) => (
              <li
                key={s.id}
                className="flex flex-wrap items-center gap-3 px-4 py-3 text-sm"
              >
                <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium text-foreground">
                    {s.target}
                  </p>
                  <p className="mono text-[11px] text-muted-foreground">
                    {s.id.slice(0, 12)} · {timeAgo(s.started_at)} ·{" "}
                    <span className="capitalize">{s.status}</span>
                  </p>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                  <span className="mono">{s.vuln_count ?? 0} {t("common.findings")}</span>
                  <span className="mono">
                    {Math.round((s.total_tokens ?? 0) / 1000)}k {t("common.tokens")}
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  <Button asChild size="sm" variant="outline">
                    <Link to={`/scans/${s.id}`}>
                      <ExternalLink className="h-3.5 w-3.5" /> {t("common.open")}
                    </Link>
                  </Button>
                  <Button asChild size="sm">
                    <a
                      href={`/api/report/${s.id}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      <Download className="h-3.5 w-3.5" /> PDF
                    </a>
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-red-400 hover:text-red-300"
                    disabled={del.isPending}
                    onClick={() => {
                      if (window.confirm(t("reports.confirmDelete"))) {
                        del.mutate(s.id);
                      }
                    }}
                  >
                    <Trash2 className="h-3.5 w-3.5" /> {t("common.delete")}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
