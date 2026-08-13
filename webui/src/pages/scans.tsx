import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useI18n } from "@/i18n";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { EmptyState, ErrorState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { useDeleteScan, useScansPage } from "@/api/queries";
import { cn, timeAgo, shortId, menuContentClass, menuItemClass } from "@/lib/utils";
import { useDebounced } from "@/lib/use-debounced";
import type { ScanListItem } from "@/types/api";
import { Pagination, DEFAULT_PAGE_SIZE } from "@/components/Pagination";
import {
  ArrowUpDown,
  Download,
  ExternalLink,
  MoreHorizontal,
  Plus,
  Search,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import NewScanDialog from "@/components/new-scan-dialog";

export default function ScansPage() {
  const { t } = useI18n();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string>("all");
  const [newOpen, setNewOpen] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);
  const debouncedQ = useDebounced(q, 300);

  // Reset to the first page whenever the filters change shape.
  useEffect(() => {
    setPage(1);
  }, [debouncedQ, status, pageSize]);

  const { data, isLoading, error, refetch } = useScansPage({
    page,
    size: pageSize,
    q: debouncedQ,
    status,
  });
  const del = useDeleteScan();

  const scans = data?.items ?? [];
  const totalItems = data?.total ?? 0;

  const visibleIds = useMemo(() => scans.map((s) => s.id), [scans]);
  const selectedVisibleCount = visibleIds.filter((id) =>
    selectedIds.has(id),
  ).length;
  const allVisibleSelected =
    visibleIds.length > 0 && selectedVisibleCount === visibleIds.length;

  function setSelected(id: string, checked: boolean) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function selectAllVisible() {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const id of visibleIds) next.add(id);
      return next;
    });
  }

  function clearSelection() {
    setSelectedIds(new Set());
  }

  async function deleteScans(ids: string[]) {
    const uniqueIds = [...new Set(ids)].filter(Boolean);
    if (!uniqueIds.length) return;
    const label =
      uniqueIds.length === 1
        ? "Permanently delete this scan?"
        : `Permanently delete ${uniqueIds.length} selected scans?`;
    if (!window.confirm(label)) return;
    for (const id of uniqueIds) {
      await del.mutateAsync(id);
    }
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const id of uniqueIds) next.delete(id);
      return next;
    });
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-sans text-2xl font-semibold tracking-tight">
            {t("scans.title")}
          </h1>
          <p className="text-sm text-muted-foreground">
            {t("scans.subtitle")}
          </p>
        </div>
      </header>

      <Card>
        <CardContent className="p-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search target or scan id…"
                className="pl-9"
              />
            </div>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger className="w-full sm:w-44">
                <SelectValue placeholder={t("scans.allStatuses")} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t("scans.allStatuses")}</SelectItem>
                <SelectItem value="running">{t("status.running")}</SelectItem>
                <SelectItem value="paused">{t("status.paused")}</SelectItem>
                <SelectItem value="saved">{t("status.saved")}</SelectItem>
                <SelectItem value="finished">{t("status.finished")}</SelectItem>
                <SelectItem value="stopped">{t("status.stopped")}</SelectItem>
                <SelectItem value="failed">{t("status.failed")}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {scans.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
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
                onDelete={() => void deleteScans([...selectedIds])}
              />
            </div>
          )}
        </CardContent>
      </Card>

      {error ? (
        <ErrorState
          title="Could not load scans"
          description={error instanceof Error ? error.message : "Unknown error"}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : isLoading ? (
        <ScanListSkeleton />
      ) : scans.length === 0 ? (
        <EmptyState
          title="No scans match"
          description="Adjust filters or kick off a new engagement."
          action={
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="mr-1 h-4 w-4" />
              New scan
            </Button>
          }
        />
      ) : (
        <>
          <ScanTable
            scans={scans}
            selectedIds={selectedIds}
            allSelected={allVisibleSelected}
            partiallySelected={selectedVisibleCount > 0 && !allVisibleSelected}
            deleting={del.isPending}
            onSelect={setSelected}
            onSelectAll={(checked) => {
              if (checked) selectAllVisible();
              else clearSelection();
            }}
            onDelete={(id) => void deleteScans([id])}
          />
          <Card>
            <Pagination
              totalItems={totalItems}
              page={page}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              className="border-t-0"
            />
          </Card>
        </>
      )}

      <NewScanDialog open={newOpen} onOpenChange={setNewOpen} />
    </div>
  );
}

function ScanTable({
  scans,
  selectedIds,
  allSelected,
  partiallySelected,
  deleting,
  onSelect,
  onSelectAll,
  onDelete,
}: {
  scans: ScanListItem[];
  selectedIds: Set<string>;
  allSelected: boolean;
  partiallySelected: boolean;
  deleting: boolean;
  onSelect: (id: string, checked: boolean) => void;
  onSelectAll: (checked: boolean) => void;
  onDelete: (id: string) => void;
}) {
  const { t } = useI18n();
  return (
    <Card>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <Th className="w-10 pl-4">
                  <SelectCheckbox
                    checked={allSelected}
                    indeterminate={partiallySelected}
                    onCheckedChange={onSelectAll}
                    label="Select all visible scans"
                  />
                </Th>
                <Th className="pl-4">
                  Target{" "}
                  <ArrowUpDown className="ml-1 inline h-3 w-3 opacity-60" />
                </Th>
                <Th>{t("scans.col.status")}</Th>
                <Th>{t("scans.col.findings")}</Th>
                <Th>{t("scans.col.tokens")}</Th>
                <Th>{t("scans.col.started")}</Th>
                <Th className="w-12 pr-4 text-right">{t("scans.col.actions")}</Th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr
                  key={s.id}
                  className={cn(
                    "group border-b border-border/60 last:border-0 transition-colors hover:bg-muted/30",
                    selectedIds.has(s.id) && "bg-muted/20",
                  )}
                >
                  <Td className="pl-4">
                    <SelectCheckbox
                      checked={selectedIds.has(s.id)}
                      onCheckedChange={(checked) => onSelect(s.id, checked)}
                      label={`Select scan ${s.target}`}
                    />
                  </Td>
                  <Td className="pl-4">
                    <Link to={`/scans/${s.id}`} className="block">
                      <div className="mono text-sm font-medium text-foreground group-hover:text-primary">
                        {s.target}
                      </div>
                      <div className="text-xs text-muted-foreground mono">
                        {shortId(s.id, 12)}
                      </div>
                      {!!s.sub_scan_total && (
                        <div className="mt-1 flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
                          <span>{s.sub_scan_total} subdomains</span>
                          <span>·</span>
                          <span>{s.sub_scan_completed ?? 0} scanned</span>
                          {!!s.sub_scan_running && (
                            <>
                              <span>·</span>
                              <span>{s.sub_scan_running} running</span>
                            </>
                          )}
                          <span>·</span>
                          <span>{s.sub_scan_remaining ?? 0} remaining</span>
                        </div>
                      )}
                    </Link>
                  </Td>
                  <Td>
                    <ScanStatusPill status={s.status} />
                  </Td>
                  <Td>
                    <div className="inline-flex items-center gap-1 mono text-xs">
                      <ShieldAlert
                        className={
                          s.vuln_count > 0
                            ? "h-3 w-3 text-amber-400"
                            : "h-3 w-3 text-muted-foreground"
                        }
                      />
                      {s.vuln_count ?? 0}
                    </div>
                  </Td>
                  <Td className="mono text-xs text-muted-foreground">
                    {s.total_tokens ? s.total_tokens.toLocaleString() : "—"}
                  </Td>
                  <Td className="pr-4">
                    <span className="text-muted-foreground">
                      {timeAgo(s.started_at)}
                    </span>
                  </Td>
                  <Td className="pr-4 text-right">
                    <RowActionMenu
                      scan={s}
                      deleting={deleting}
                      onDelete={() => onDelete(s.id)}
                    />
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

function Th({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <th className={`px-3 py-2 text-left font-medium ${className}`}>
      {children}
    </th>
  );
}
function Td({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <td className={`px-3 py-3 align-middle ${className}`}>{children}</td>;
}

function SelectCheckbox({
  checked,
  indeterminate = false,
  onCheckedChange,
  label,
}: {
  checked: boolean;
  indeterminate?: boolean;
  onCheckedChange: (checked: boolean) => void;
  label: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate;
  }, [indeterminate]);
  return (
    <input
      ref={ref}
      type="checkbox"
      checked={checked}
      aria-label={label}
      onChange={(event) => onCheckedChange(event.currentTarget.checked)}
      className="h-4 w-4 rounded border-border bg-input accent-primary focus:outline-none focus:ring-1 focus:ring-ring"
    />
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
  scan,
  deleting,
  onDelete,
}: {
  scan: ScanListItem;
  deleting: boolean;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button
          size="icon"
          variant="ghost"
          aria-label={`Actions for ${scan.target}`}
        >
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className={menuContentClass}>
          <DropdownMenu.Item asChild className={menuItemClass}>
            <Link to={`/scans/${scan.id}`}>
              <ExternalLink className="h-3.5 w-3.5" />
              Open details
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Item asChild className={menuItemClass}>
            <a href={`/api/report/${scan.id}`} target="_blank" rel="noreferrer">
              <Download className="h-3.5 w-3.5" />
              Download PDF
            </a>
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
            Delete scan
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function ScanListSkeleton() {
  return (
    <Card>
      <CardContent className="space-y-2 p-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </CardContent>
    </Card>
  );
}
