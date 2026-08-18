import { useMemo, type ReactNode } from "react";
import { useI18n } from "@/i18n";
import { Link } from "react-router-dom";
import { keepPreviousData, useQueries, useQuery } from "@tanstack/react-query";
import type {
  FindingsSummaryResponse,
  ScanRecord,
  VulnSummary,
} from "@/types/api";
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  BarChart3,
  Cpu,
  HardDrive,
  Layers,
  Plus,
  Radio,
  ShieldAlert,
  Target,
} from "lucide-react";
import { MetricCard } from "@/components/metric-card";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { EmptyState, ErrorState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { LiveFeed } from "@/components/live-feed";
import { mergeFeedEvents, toFeedEvent, useWSStore } from "@/store/ws";
import { api } from "@/api/client";
import {
  qk,
  useInstances,
  useQueueStatus,
  useScansList,
  useStatus,
} from "@/api/queries";
import {
  normalizeSeverity,
  severityRank,
  shortId,
  timeAgo,
} from "@/lib/utils";

export default function OverviewPage() {
  const { t } = useI18n();
  const { data: status } = useStatus();
  const { data: instances, isLoading: instancesLoading, error: instancesError } =
    useInstances();
  const { data: scanList } = useScansList();
  const { data: queue } = useQueueStatus();
  const events = useWSStore((s) => s.events);
  const scanDetailIds = useMemo(
    () => (scanList ?? []).map((s) => s.id),
    [scanList],
  );
  const scanDetailQueries = useQueries({
    queries: scanDetailIds.map((id) => ({
      queryKey: ["scan", id],
      queryFn: () => api.getScan(id),
      staleTime: 30_000,
      // Retain the previous successful result while a refetch is in
      // flight. Without this the reducer below would see `data ===
      // undefined` for every query that re-enters `isFetching`, causing
      // the totals widget to flicker as scans take turns refetching.
      placeholderData: keepPreviousData,
    })),
  });

  const allInstances = instances?.instances ?? [];
  const runningInstances = allInstances.filter((i) => i.status === "running");
  const activeInstance = runningInstances[0];
  const activeEventInstanceIds = useMemo(
    () =>
      allInstances
        .filter((i) => isActiveStatus(i.status))
        .map((i) => i.id)
        .slice(0, 5),
    [allInstances],
  );
  const eventHistoryQueries = useQueries({
    queries: activeEventInstanceIds.map((id) => ({
      queryKey: qk.instanceEvents(id),
      queryFn: () => api.instanceEvents(id),
      staleTime: 1000,
      refetchInterval: 5000,
    })),
  });
  const hydratedEvents = useMemo(() => {
    const persisted = eventHistoryQueries.flatMap((q, queryIndex) =>
      (q.data ?? []).map((event, eventIndex) =>
        toFeedEvent(
          event,
          `instance:${activeEventInstanceIds[queryIndex] || queryIndex}`,
          eventIndex,
        ),
      ),
    );
    return mergeFeedEvents(persisted, events).slice(-80);
  }, [activeEventInstanceIds, eventHistoryQueries, events]);

  const aggregateVulns = useMemo(() => {
    const map = new Map<string, { vuln: VulnSummary; instanceId: string }>();
    const add = (v: VulnSummary, instanceId: string) => {
      const key = v.id || `${instanceId}:${v.title}:${v.endpoint}:${v.severity}`;
      if (!map.has(key)) map.set(key, { vuln: v, instanceId });
    };
    for (const inst of allInstances) {
      for (const v of inst.vulns || []) {
        add(v, inst.id);
      }
    }
    for (const q of scanDetailQueries) {
      const rec = q.data as ScanRecord | null | undefined;
      // Skip ONLY on initial-load `undefined`. Once a scan has produced
      // any data, `placeholderData: keepPreviousData` keeps `q.data`
      // populated across refetches so the contribution does not drop to
      // zero. An empty `vulns` array is a legitimate value and must not
      // be treated as missing.
      if (!rec) continue;
      const vulns = rec.vulns ?? [];
      for (const v of vulns) {
        add(v, rec.instance_id || rec.id);
      }
    }
    return Array.from(map.values());
  }, [allInstances, scanDetailQueries]);

  // Stable on-disk totals from /api/findings/summary. Polled every 10s
  // and used to drive the Overview totals widget so the count never
  // drops during refetch. Shared qk.findingsSummary key means
  // /findings reads the same cache entry.
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

  const scanListFindings = useMemo(
    () => (scanList ?? []).reduce((sum, s) => sum + (s.vuln_count ?? 0), 0),
    [scanList],
  );
  // Prefer the stable on-disk total from /api/findings/summary when it
  // resolves; fall back to the in-memory tally on initial load so the
  // widget is never blank. Math.max keeps the displayed total from
  // dropping below either source while data is still loading in.
  const summaryTotal = useMemo(() => {
    const t = summary.data?.totals;
    if (!t) return 0;
    return t.critical + t.high + t.medium + t.low + t.info;
  }, [summary.data]);
  const totalFindings = Math.max(
    summaryTotal,
    scanListFindings,
    aggregateVulns.length,
  );
  const criticalHigh = useMemo(() => {
    if (summary.data?.totals) {
      return summary.data.totals.critical + summary.data.totals.high;
    }
    return aggregateVulns.filter((v) => {
      const s = normalizeSeverity(v.vuln.severity);
      return s === "critical" || s === "high";
    }).length;
  }, [aggregateVulns, summary.data]);
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const { vuln } of aggregateVulns) {
      counts[normalizeSeverity(vuln.severity)] += 1;
    }
    return counts;
  }, [aggregateVulns]);
  const severityLoading =
    totalFindings > 0 &&
    aggregateVulns.length === 0 &&
    scanDetailQueries.some((q) => q.isLoading || q.isFetching);

  // ScanInstance.targets is a comma-separated string; trim each entry so we
  // collapse "a.com, b.com" and "a.com,b.com" to the same logical target.
  const targetsScanned = new Set(
    allInstances.flatMap((i) =>
      i.targets
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    ),
  ).size;

  const recentScans = allInstances.slice(0, 6);

  const recentCritical = useMemo(() => {
    return [...aggregateVulns]
      .sort((a, b) => severityRank(b.vuln.severity) - severityRank(a.vuln.severity))
      .filter((v) => {
        const s = normalizeSeverity(v.vuln.severity);
        return s === "critical" || s === "high";
      })
      .slice(0, 5);
  }, [aggregateVulns]);

  const resources = instances?.resources;
  const queueCount = queue?.available ? queue.total_remaining ?? queue.remaining ?? 0 : 0;
  const latestScan = recentScans[0];
  const completedCount = allInstances.filter((i) => i.status === "finished").length;
  const stoppedCount = allInstances.filter((i) => i.status === "stopped").length;

  if (instancesError) {
    return (
      <ErrorState
        title="Failed to load dashboard"
        description={(instancesError as Error).message}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t("overview.title")}</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Command center for scans, findings, and live activity.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <MetricCard
          label="Active"
          value={runningInstances.length}
          hint={
            activeInstance
              ? `${activeInstance.name || activeInstance.targets.split(",")[0]}`
              : "No active scans"
          }
          to={activeInstance ? `/scans/${activeInstance.id}` : "/scans"}
          icon={<Activity className="h-3.5 w-3.5" />}
          accent={runningInstances.length > 0 ? "success" : "default"}
        />
        <MetricCard
          label="Findings"
          value={totalFindings}
          hint={`${scanList?.length || 0} scans on disk`}
          to="/findings"
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
        />
        <MetricCard
          label="Crit / High"
          value={severityLoading ? "..." : criticalHigh}
          hint={
            severityLoading
              ? "Checking severity"
              : criticalHigh > 0
                ? "Needs review"
                : "All clear"
          }
          to="/findings"
          icon={<AlertOctagon className="h-3.5 w-3.5" />}
          accent={criticalHigh > 0 ? "critical" : "default"}
        />
        <MetricCard
          label="Targets"
          value={targetsScanned}
          hint={targetsScanned === 1 ? "1 host" : `${targetsScanned} hosts`}
          to="/scans"
          icon={<Target className="h-3.5 w-3.5" />}
        />
        <MetricCard
          label="Phase"
          value={status?.current_phase ?? "—"}
          hint={
            status?.current_phase
              ? `Methodology phase ${status.current_phase}`
              : "Idle"
          }
          icon={<Layers className="h-3.5 w-3.5" />}
        />
        <MetricCard
          label="Queue"
          value={queueCount}
          hint={
            queue?.available
              ? `${queue.queue_count ?? 1} queue${(queue.queue_count ?? 1) === 1 ? "" : "s"} · ${queue.paused ? "paused" : "resumable"}`
              : "Empty"
          }
          to={queue?.available ? "/scans" : undefined}
          icon={<Radio className="h-3.5 w-3.5" />}
          accent={queueCount > 0 ? "warning" : "default"}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 lg:items-start">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between py-4">
              <CardTitle>{t("overview.recentScans")}</CardTitle>
              <Button asChild size="sm" variant="ghost">
                <Link to="/scans">
                  View all <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </Button>
            </CardHeader>
            <CardContent className="p-0">
              {instancesLoading ? (
                <div className="space-y-2 p-4">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-10" />
                  ))}
                </div>
              ) : recentScans.length === 0 ? (
                <EmptyState
                  title="No scans yet"
                  description="Launch your first scan to start collecting findings."
                  action={
                    <Button asChild size="sm">
                      <Link to="/scans/new">
                        <Plus className="h-3.5 w-3.5" /> New Scan
                      </Link>
                    </Button>
                  }
                  className="m-4"
                />
              ) : (
                <div className="divide-y divide-border">
                  {recentScans.map((s) => (
                    <Link
                      key={s.id}
                      to={`/scans/${s.id}`}
                      className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-accent/40"
                    >
                      <ScanStatusPill status={s.status} />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium truncate">
                          {s.name || s.targets.split(",")[0] || "Untitled scan"}
                        </p>
                        <p className="text-xs text-muted-foreground mono truncate">
                          {s.targets}
                        </p>
                      </div>
                      <div className="hidden md:block text-right text-xs text-muted-foreground mono">
                        <div>{s.vuln_count} findings</div>
                        <div>{timeAgo(s.started_at)}</div>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between py-4">
              <CardTitle>{t("overview.liveActivity")}</CardTitle>
              <Button asChild size="sm" variant="ghost">
                <Link to="/live">
                  Open feed <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </Button>
            </CardHeader>
            <CardContent className="p-0">
              <LiveFeed
                events={hydratedEvents.slice(-50)}
                filter="all"
                onFilterChange={() => {}}
                showControls={false}
                className="border-0"
                emptyTitle="Waiting for events"
                emptyDescription="When a scan is running, its live events appear here."
              />
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between py-4">
              <CardTitle>{t("overview.systemHealth")}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <Row
                icon={<Cpu className="h-3.5 w-3.5" />}
                label="CPU load (1m)"
                value={
                  resources
                    ? `${resources.cpu_load_1m?.toFixed(2)} · ${resources.cpu_cores} cores`
                    : "—"
                }
              />
              <Row
                icon={<HardDrive className="h-3.5 w-3.5" />}
                label="RAM available"
                value={
                  resources
                    ? `${(resources.ram_available_mb / 1024).toFixed(1)} GB / ${(resources.ram_total_mb / 1024).toFixed(1)} GB`
                    : "—"
                }
              />
              <Row
                icon={<HardDrive className="h-3.5 w-3.5" />}
                label="Disk free"
                value={
                  resources
                    ? `${(resources.disk_free_mb / 1024).toFixed(1)} GB`
                    : "—"
                }
              />
              <Row
                icon={<Layers className="h-3.5 w-3.5" />}
                label="Resource level"
                value={
                  resources ? (
                    <span className="capitalize">
                      {resources.level} · max {resources.effective_max_instances}
                    </span>
                  ) : (
                    "—"
                  )
                }
              />
              {resources && shouldShowResourceReason(resources) && (
                <p className="rounded border border-border bg-muted/40 px-2 py-1 text-[11px] text-muted-foreground mono">
                  {resources.reason}
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between py-4">
              <CardTitle>{t("overview.criticalFindings")}</CardTitle>
              <Button asChild size="sm" variant="ghost">
                <Link to="/findings">
                  All findings <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </Button>
            </CardHeader>
            <CardContent className="p-0">
              {recentCritical.length === 0 ? (
                <EmptyState
                  title="No critical findings"
                  description="Critical and high severity findings appear here as they are discovered."
                  className="m-4"
                />
              ) : (
                <ul className="divide-y divide-border">
                  {recentCritical.map(({ vuln, instanceId }) => (
                    <li key={`${instanceId}-${vuln.id}`}>
                      {/* Findings deep-link route doesn't exist; route to the
                          owning scan, where the Findings tab renders this vuln. */}
                      <Link
                        to={`/scans/${instanceId}`}
                        className="block px-5 py-3 transition-colors hover:bg-accent/40"
                      >
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={vuln.severity} />
                          <span className="text-sm font-medium truncate">
                            {vuln.title}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-muted-foreground mono truncate">
                          {vuln.endpoint || vuln.target || shortId(instanceId)}
                        </p>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between py-4">
              <CardTitle>{t("overview.findingMix")}</CardTitle>
              <BarChart3 className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent className="space-y-3">
              {(["critical", "high", "medium", "low", "info"] as const).map(
                (severity) => (
                  <SeverityRow
                    key={severity}
                    severity={severity}
                    count={severityCounts[severity]}
                    total={Math.max(aggregateVulns.length, 1)}
                  />
                ),
              )}
              <p className="text-[11px] text-muted-foreground">
                {aggregateVulns.length > 0
                  ? `${aggregateVulns.length.toLocaleString()} findings with loaded severity detail`
                  : severityLoading
                    ? "Severity detail is still loading"
                    : "No severity detail loaded yet"}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="py-4">
              <CardTitle>{t("overview.operations")}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <Row
                icon={<Activity className="h-3.5 w-3.5" />}
                label="Running"
                value={`${runningInstances.length} active`}
              />
              <Row
                icon={<Radio className="h-3.5 w-3.5" />}
                label="Queue"
	                value={
	                  queue?.available
	                    ? queue.paused
	                      ? `${queueCount} paused`
	                      : `${queueCount} remaining`
	                    : "empty"
	                }
              />
              <Row
                icon={<Layers className="h-3.5 w-3.5" />}
                label="Current phase"
                value={status?.current_phase ? `phase ${status.current_phase}` : "idle"}
              />
              <Row
                icon={<ShieldAlert className="h-3.5 w-3.5" />}
                label="Completed / stopped"
                value={`${completedCount} / ${stoppedCount}`}
              />
              <SeparatorLine />
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-muted-foreground">{t("overview.latestScan")}</p>
                  <p className="mt-0.5 truncate text-sm text-foreground">
                    {latestScan?.name ||
                      latestScan?.targets.split(",")[0] ||
                      "No scans yet"}
                  </p>
                </div>
                {latestScan && (
                  <Button asChild size="sm" variant="outline" className="h-8 shrink-0">
                    <Link to={`/scans/${latestScan.id}`}>
                      Open <ArrowRight className="h-3.5 w-3.5" />
                    </Link>
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Row({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-2 text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div className="text-foreground text-right mono">{value}</div>
    </div>
  );
}

function SeverityRow({
  severity,
  count,
  total,
}: {
  severity: "critical" | "high" | "medium" | "low" | "info";
  count: number;
  total: number;
}) {
  const width = count > 0 ? Math.max(8, Math.round((count / total) * 100)) : 0;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <SeverityBadge severity={severity} />
        <span className="mono text-xs text-foreground">{count}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-sm bg-muted">
        <div
          className={`h-full rounded-sm ${severityBarClass(severity)}`}
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}

function severityBarClass(severity: "critical" | "high" | "medium" | "low" | "info") {
  switch (severity) {
    case "critical":
      return "bg-red-500";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-amber-400";
    case "low":
      return "bg-blue-400";
    case "info":
      return "bg-neutral-500";
  }
}

function SeparatorLine() {
  return <div className="h-px bg-border" />;
}

function isActiveStatus(status?: string): boolean {
  const s = (status || "").toLowerCase();
  return s === "running" || s === "pending" || s === "paused";
}

function shouldShowResourceReason(resources?: { level?: string; reason?: string }): boolean {
  const reason = resources?.reason?.trim();
  if (!reason) return false;
  const level = (resources?.level || "").trim().toLowerCase();
  return level !== "ok" && !reason.toLowerCase().startsWith("ok");
}
