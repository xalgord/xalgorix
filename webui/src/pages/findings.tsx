import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useI18n } from "@/i18n";
import { Link } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import {
  keepPreviousData,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  ExternalLink,
  Filter,
  MoreHorizontal,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge } from "@/components/severity-badge";
import { VerificationBadge } from "@/components/verification-badge";
import { EmptyState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DEFAULT_PAGE_SIZE,
  PAGE_SIZE_OPTIONS,
  Pagination,
} from "@/components/Pagination";
import { useDeleteVuln, useScansList, useFindingsList, qk } from "@/api/queries";
import type { FindingsSummaryResponse } from "@/types/api";
import { dedupFindings, type FlatFinding } from "@/lib/findings";
import {
  cn,
  normalizeSeverity,
  timeAgo,
  menuContentClass,
  menuItemClass,
} from "@/lib/utils";

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export default function FindingsPage() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const { data: scans } = useScansList();
  const del = useDeleteVuln();
  // Scan ids are kept only for the "across N scans" header label and as the
  // refresh-target count. The findings themselves no longer fan out one
  // getScan() request per scan; they come from a single server-side walk.
  const ids = useMemo(() => (scans ?? []).map((s) => s.id), [scans]);

  const findingsQuery = useFindingsList();
  const isLoading = findingsQuery.isLoading;

  const findings = useMemo<FlatFinding[]>(
    // The server already dedups + sorts, but dedupFindings is idempotent and
    // keeps the client resilient if the payload shape ever changes.
    () => dedupFindings(findingsQuery.data ?? []),
    [findingsQuery.data],
  );

  // Stable on-disk totals from /api/findings/summary. Polled every 10s
  // and used both for the totals row and for the "updated Xs ago"
  // indicator (sourced from the response's `as_of` field). The shared
  // qk.findingsSummary key means /overview reads the same cache entry.
  const summary = useQuery<FindingsSummaryResponse>({
    queryKey: qk.findingsSummary,
    queryFn: async () => {
      const res = await fetch("/api/findings/summary", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as FindingsSummaryResponse;
    },
    refetchInterval: 10_000,
    staleTime: 5_000,
    placeholderData: keepPreviousData,
  });

  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<string>("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severity !== "all" && normalizeSeverity(f.severity) !== severity) return false;
      if (!query) return true;
      const q = query.toLowerCase();
      return (
        (f.title || "").toLowerCase().includes(q) ||
        (f.endpoint || "").toLowerCase().includes(q) ||
        (f.scan_target || "").toLowerCase().includes(q) ||
        (f.cve || "").toLowerCase().includes(q) ||
        (f.cwe_id || "").toLowerCase().includes(q) ||
        (f.owasp || "").toLowerCase().includes(q)
      );
    });
  }, [findings, query, severity]);

  // Reset to first page when filters or page size changes so we never
  // strand the user past the new last page. (Page-size changes from
  // the URL hydrator path also pass through here.)
  useEffect(() => {
    setPage(1);
  }, [query, severity, pageSize]);

  // Clamp current page when the underlying list shrinks (e.g. after a
  // delete). Without this, the slice below would silently render empty.
  const totalPages = Math.max(1, Math.ceil(filtered.length / Math.max(1, pageSize)));
  const safePage = Math.min(Math.max(1, page), totalPages);
  useEffect(() => {
    if (safePage !== page) setPage(safePage);
  }, [safePage, page]);

  const paged = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, safePage, pageSize]);

  const visibleKeys = useMemo(() => paged.map((f) => `${f.scan_id}:${f.id}`), [paged]);
  const selectedVisibleCount = visibleKeys.filter((k) => selectedIds.has(k)).length;
  const allVisibleSelected = visibleKeys.length > 0 && selectedVisibleCount === visibleKeys.length;

  useEffect(() => {
    const allKeys = new Set(findings.map((f) => `${f.scan_id}:${f.id}`));
    setSelectedIds((current) => {
      const next = new Set([...current].filter((k) => allKeys.has(k)));
      return next.size === current.size ? current : next;
    });
  }, [findings]);

  function setSelected(key: string, checked: boolean) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (checked) next.add(key);
      else next.delete(key);
      return next;
    });
  }

  function selectAllVisible() {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const k of visibleKeys) next.add(k);
      return next;
    });
  }

  function clearSelection() {
    setSelectedIds(new Set());
  }

  async function deleteFindings(keys: string[]) {
    const unique = [...new Set(keys)].filter(Boolean);
    if (!unique.length) return;
    const label =
      unique.length === 1
        ? "Permanently delete this finding?"
        : `Permanently delete ${unique.length} selected findings?`;
    if (!window.confirm(label)) return;
    for (const key of unique) {
      const [scanId, vulnId] = key.split(":");
      if (scanId && vulnId) {
        await del.mutateAsync({ scanId, vulnId });
      }
    }
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const k of unique) next.delete(k);
      return next;
    });
  }

  // Manual refresh: invalidate the findings list plus the summary query so
  // the totals row and the list re-fetch in lockstep.
  function refreshAll() {
    qc.invalidateQueries({ queryKey: qk.findingsList });
    qc.invalidateQueries({ queryKey: qk.findingsSummary });
  }

  // Prefer the stable on-disk totals from /api/findings/summary. Fall
  // back to the in-page tally only on initial load before the summary
  // request resolves, so the totals row is never blank.
  const counts = useMemo<SeverityCounts>(() => {
    if (summary.data?.totals) return summary.data.totals;
    const out: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => {
      const sev = normalizeSeverity(f.severity);
      if (sev in out) out[sev as keyof SeverityCounts] += 1;
    });
    return out;
  }, [findings, summary.data]);

  const updatedLabel = summary.data?.as_of ? timeAgo(summary.data.as_of) : "—";
  const isRefreshing = summary.isFetching || findingsQuery.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("findings.title")}</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Vulnerabilities across {ids.length} scan{ids.length === 1 ? "" : "s"}, ranked by
            severity.
          </p>
        </div>
        <div className="flex flex-col items-stretch gap-2 sm:items-end">
          <div className="grid grid-cols-5 gap-1.5 sm:flex sm:gap-2">
            {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
              const dot =
                s === "critical"
                  ? "bg-red-500"
                  : s === "high"
                    ? "bg-orange-500"
                    : s === "medium"
                      ? "bg-amber-400"
                      : s === "low"
                        ? "bg-blue-400"
                        : "bg-neutral-500";
              return (
                <div
                  key={s}
                  className="rounded-md border border-border bg-card px-3 py-2 text-center min-w-[64px]"
                >
                  <p className="mono text-lg font-semibold leading-none tabular-nums">
                    {counts[s] ?? 0}
                  </p>
                  <p className="mt-1 flex items-center justify-center gap-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                    <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
                    {s}
                  </p>
                </div>
              );
            })}
          </div>
          <div className="flex items-center justify-end gap-2 text-[11px] text-muted-foreground">
            <span className="mono">updated {updatedLabel}</span>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={refreshAll}
              disabled={isRefreshing}
              aria-label="Refresh findings"
            >
              <RefreshCw
                className={cn("h-3.5 w-3.5", isRefreshing && "animate-spin")}
              />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      <Card>
        <CardContent className="flex flex-col gap-3 p-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by title, endpoint, host, or CVE…"
              className="pl-8"
            />
          </div>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="w-full sm:w-44">
              <Filter className="h-3.5 w-3.5" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t("findings.allSeverities")}</SelectItem>
              <SelectItem value="critical">{t("severity.critical")}</SelectItem>
              <SelectItem value="high">{t("severity.high")}</SelectItem>
              <SelectItem value="medium">{t("severity.medium")}</SelectItem>
              <SelectItem value="low">{t("severity.low")}</SelectItem>
              <SelectItem value="info">{t("severity.info")}</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
        {filtered.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-t border-border px-3 py-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={allVisibleSelected ? clearSelection : selectAllVisible}
            >
              {allVisibleSelected ? "Clear selection" : "Select all"}
            </Button>
            <span className="text-xs text-muted-foreground">
              {selectedIds.size} selected
            </span>
            <BulkActionMenu
              disabled={selectedIds.size === 0 || del.isPending}
              selectedCount={selectedIds.size}
              onDelete={() => void deleteFindings([...selectedIds])}
            />
          </div>
        )}
      </Card>

      <Card className="overflow-hidden">
        {isLoading && findings.length === 0 ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-6 w-6" />}
            title="No matching findings"
            description="Try widening your filters or run a new scan."
          />
        ) : (
          <>
            <ul className="divide-y divide-border">
              {paged.map((f) => {
                const key = `${f.scan_id}:${f.id}`;
                return (
                  <li
                    key={key}
                    className={cn(
                      "group flex items-start gap-3 px-4 py-3 text-sm transition-colors hover:bg-muted/30",
                      selectedIds.has(key) && "bg-muted/20",
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={selectedIds.has(key)}
                      aria-label={`Select finding ${f.title}`}
                      onChange={(e) => setSelected(key, e.currentTarget.checked)}
                      className="mt-1 h-4 w-4 shrink-0 rounded border-border bg-input accent-primary focus:outline-none focus:ring-1 focus:ring-ring"
                    />
                    <Link to={`/scans/${f.scan_id}`} className="block flex-1 min-w-0">
                      <div className="flex flex-wrap items-start gap-2">
                        <SeverityBadge severity={f.severity} />
                        <p className="flex-1 font-medium text-foreground truncate">
                          {f.title}
                        </p>
                        <span className="mono text-[11px] text-muted-foreground">
                          {timeAgo(f.scan_started_at)}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                        <span className="mono truncate max-w-[36ch]">{f.endpoint || f.scan_target}</span>
                        {f.cve && (
                          <Badge variant="outline" className="mono text-[10px]">
                            {f.cve}
                          </Badge>
                        )}
                        {f.cwe_id && (
                          <Badge variant="outline" className="mono text-[10px] text-emerald-400 border-emerald-400/30">
                            {f.cwe_id}
                          </Badge>
                        )}
                        {f.owasp && (
                          <Badge variant="outline" className="mono text-[10px] text-amber-400 border-amber-400/30">
                            {f.owasp}
                          </Badge>
                        )}
                        <VerificationBadge verified={f.verified} tags={f.tags} />
                        {typeof f.cvss === "number" && f.cvss > 0 && (
                          <span className="mono">CVSS {f.cvss.toFixed(1)}</span>
                        )}
                        <span className="ml-auto truncate">→ {f.scan_target}</span>
                      </div>
                    </Link>
                    <RowActionMenu
                      finding={f}
                      deleting={del.isPending}
                      onDelete={() => void deleteFindings([key])}
                    />
                  </li>
                );
              })}
            </ul>
            <Pagination
              totalItems={filtered.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={(size) => {
                if ((PAGE_SIZE_OPTIONS as readonly number[]).includes(size)) {
                  setPageSize(size);
                }
              }}
            />
          </>
        )}
      </Card>
    </div>
  );
}

function BulkActionMenu({
  disabled,
  selectedCount,
  onDelete,
}: {
  disabled: boolean;
  selectedCount: number;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button size="sm" variant="secondary" disabled={disabled}>
          Actions
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="start" className={menuContentClass}>
          <DropdownMenu.Label className="px-2 py-1.5 text-xs text-muted-foreground">
            {selectedCount} selected
          </DropdownMenu.Label>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            className={cn(menuItemClass, "text-red-400 focus:text-red-300")}
            onSelect={(event) => {
              event.preventDefault();
              onDelete();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete selected
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function RowActionMenu({
  finding,
  deleting,
  onDelete,
}: {
  finding: FlatFinding;
  deleting: boolean;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button
          size="icon"
          variant="ghost"
          aria-label={`Actions for ${finding.title}`}
          className="shrink-0"
        >
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className={menuContentClass}>
          <DropdownMenu.Item asChild className={menuItemClass}>
            <Link to={`/scans/${finding.scan_id}`}>
              <ExternalLink className="h-3.5 w-3.5" />
              Open scan
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            disabled={deleting}
            className={cn(
              menuItemClass,
              "text-red-400 focus:text-red-300 data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
            )}
            onSelect={(event) => {
              event.preventDefault();
              onDelete();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete finding
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
