import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState, ErrorState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  useSchedulesList,
  useCreateSchedule,
  useUpdateSchedule,
  useDeleteSchedule,
  useTriggerSchedule,
  useAuthProfiles,
  useLLMSettings,
  useProviders,
} from "@/api/queries";
import { cn, menuContentClass, menuItemClass } from "@/lib/utils";
import type { ScanSchedule } from "@/types/api";
import {
  Clock,
  MoreHorizontal,
  Plus,
  Search,
  Trash2,
  Edit2,
  Play,
  Upload,
  ImageIcon,
  X,
  Loader2,
} from "lucide-react";
import { api } from "@/api/client";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
type ActivityMode = "active" | "passive";

export default function SchedulesPage() {
  const { data, isLoading, error, refetch } = useSchedulesList();
  const createMutation = useCreateSchedule();
  const updateMutation = useUpdateSchedule();
  const deleteMutation = useDeleteSchedule();
  const triggerMutation = useTriggerSchedule();
  const llmQuery = useLLMSettings();

  const [q, setQ] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState<ScanSchedule | null>(
    null,
  );

  // Form State
  const [name, setName] = useState("");
  const [interval, setInterval] = useState("daily");
  const [targetsText, setTargetsText] = useState("");
  const [scanMode, setScanMode] = useState("single");
  const [reconMode, setReconMode] = useState<ActivityMode>("active");
  const [scanIntensity, setScanIntensity] = useState<ActivityMode>("active");
  const [instruction, setInstruction] = useState("");
  const [model, setModel] = useState("");
  // Optional "<provider>:<profileId>" key naming a stored AuthProfile
  // (provider-catalog-and-oauth, R11.1, R14.4). Empty string means
  // "let the server pick" — don't send provider_profile at trigger
  // time and the legacy / catalog-default path applies.
  const [providerProfile, setProviderProfile] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [logoPath, setLogoPath] = useState("");
  const [logoFileName, setLogoFileName] = useState("");
  const [logoUploading, setLogoUploading] = useState(false);
  const [discordWebhook, setDiscordWebhook] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [formError, setFormError] = useState<string | null>(null);

  const schedules = useMemo<ScanSchedule[]>(() => {
    let list: ScanSchedule[] = data ?? [];
    if (q.trim()) {
      const needle = q.toLowerCase();
      list = list.filter(
        (s) =>
          s.name.toLowerCase().includes(needle) ||
          s.targets.some((t) => t.toLowerCase().includes(needle)),
      );
    }
    return list;
  }, [data, q]);

  // Provider profile picker source. Mirrors new-scan.tsx — we look up
  // each profile's catalog entry to render `displayName · profileId`.
  // When neither query has loaded yet the picker collapses to the
  // single "Server default" option.
  const profilesQuery = useAuthProfiles();
  const catalogQuery = useProviders();
  const profileOptions = useMemo(() => {
    const profiles = profilesQuery.data ?? [];
    const catalog = catalogQuery.data ?? [];
    const byID = new Map(catalog.map((e) => [e.id, e]));
    return profiles.map((p) => {
      const entry = byID.get(p.provider);
      const display = entry?.displayName ?? p.provider;
      return {
        value: `${p.provider}:${p.profileId}`,
        label: `${display} · ${p.profileId}`,
      };
    });
  }, [profilesQuery.data, catalogQuery.data]);

  // Open dialog for new schedule
  function handleNewSchedule() {
    setEditingSchedule(null);
    setName("");
    setInterval("daily");
    setTargetsText("");
    setScanMode("single");
    setReconMode("active");
    setScanIntensity("active");
    setInstruction("");
    setModel("");
    setCompanyName("");
    setLogoPath("");
    setLogoFileName("");
    setDiscordWebhook("");
    setSeverityFilter([]);
    setProviderProfile("");
    setFormError(null);
    setDialogOpen(true);
  }

  // Open dialog to edit schedule
  function handleEditSchedule(sch: ScanSchedule) {
    setEditingSchedule(sch);
    setName(sch.name);
    setInterval(sch.interval);
    setTargetsText(sch.targets.join("\n"));
    setScanMode(sch.scan_mode || "single");
    const nextScanIntensity = sch.scan_intensity || "active";
    setScanIntensity(nextScanIntensity);
    setReconMode(
      nextScanIntensity === "passive" ? "passive" : sch.recon_mode || "active",
    );
    setInstruction(sch.instruction || "");
    setModel(sch.model || "");
    setCompanyName(sch.company_name || "");
    setLogoPath(sch.logo_path || "");
    setLogoFileName(sch.logo_path ? "Uploaded logo" : "");
    setDiscordWebhook(sch.discord_webhook || "");
    setSeverityFilter(sch.severity_filter || []);
    setProviderProfile(sch.provider_profile || "");
    setFormError(null);
    setDialogOpen(true);
  }

  // Toggle enabled/disabled inline
  async function handleToggleEnabled(sch: ScanSchedule, enabled: boolean) {
    try {
      await updateMutation.mutateAsync({
        id: sch.id,
        schedule: { ...sch, enabled },
      });
    } catch (err) {
      console.error("Failed to toggle schedule status:", err);
    }
  }

  // Trigger ad-hoc scan execution
  async function handleTrigger(sch: ScanSchedule) {
    if (!window.confirm(`Trigger ad-hoc scan for "${sch.name}" now?`)) return;
    try {
      await triggerMutation.mutateAsync(sch.id);
      alert("Scan triggered successfully!");
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to trigger scan");
    }
  }

  // Delete schedule
  async function handleDelete(sch: ScanSchedule) {
    if (
      !window.confirm(
        `Are you sure you want to delete the schedule "${sch.name}"?`,
      )
    )
      return;
    try {
      await deleteMutation.mutateAsync(sch.id);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete schedule");
    }
  }

  // Logo upload
  async function uploadReportLogo(file?: File) {
    if (!file) return;
    setFormError(null);
    if (!/\.(png|jpe?g)$/i.test(file.name)) {
      setFormError("Report logos must be PNG or JPEG.");
      return;
    }
    setLogoUploading(true);
    try {
      const res = await api.uploadLogo(file);
      setLogoPath(res.path);
      setLogoFileName(res.filename || file.name);
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Failed to upload logo",
      );
    } finally {
      setLogoUploading(false);
    }
  }

  // Form Submit
  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);

    const targets = targetsText
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);

    if (targets.length === 0) {
      setFormError("Provide at least one target.");
      return;
    }

    const payload = {
      name: name.trim() || undefined,
      interval,
      targets,
      scan_mode: scanMode,
      recon_mode: reconMode,
      scan_intensity: scanIntensity,
      instruction: instruction.trim() || undefined,
      model: model || undefined,
      provider_profile: providerProfile || undefined,
      company_name: companyName.trim() || undefined,
      logo_path: logoPath || undefined,
      discord_webhook: discordWebhook.trim() || undefined,
      severity_filter: severityFilter.length ? severityFilter : undefined,
      enabled: editingSchedule ? editingSchedule.enabled : true,
    } as any;

    try {
      if (editingSchedule) {
        await updateMutation.mutateAsync({
          id: editingSchedule.id,
          schedule: payload,
        });
      } else {
        await createMutation.mutateAsync(payload);
      }
      setDialogOpen(false);
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Failed to save schedule",
      );
    }
  }

  function toggleSeverity(sev: string) {
    setSeverityFilter((cur) =>
      cur.includes(sev) ? cur.filter((p) => p !== sev) : [...cur, sev],
    );
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-sans text-2xl font-semibold tracking-tight">
            Schedules
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage automated recurring scans running on configured intervals.
          </p>
        </div>
        <Button onClick={handleNewSchedule} className="self-start sm:self-auto">
          <Plus className="mr-1 h-4 w-4" />
          New schedule
        </Button>
      </header>

      <Card>
        <CardContent className="p-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search schedule name or target…"
              className="pl-9"
            />
          </div>
        </CardContent>
      </Card>

      {error ? (
        <ErrorState
          title="Could not load schedules"
          description={error instanceof Error ? error.message : "Unknown error"}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : isLoading ? (
        <ScheduleListSkeleton />
      ) : schedules.length === 0 ? (
        <EmptyState
          title="No scheduled scans"
          description="Automate recurring testing across your target landscape."
          action={
            <Button onClick={handleNewSchedule}>
              <Plus className="mr-1 h-4 w-4" />
              Create schedule
            </Button>
          }
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium">Name</th>
                    <th className="px-4 py-3 text-left font-medium">
                      Interval
                    </th>
                    <th className="px-4 py-3 text-left font-medium">Targets</th>
                    <th className="px-4 py-3 text-left font-medium">
                      Last Run
                    </th>
                    <th className="px-4 py-3 text-left font-medium">
                      Next Run
                    </th>
                    <th className="px-4 py-3 text-left font-medium">Status</th>
                    <th className="px-4 py-3 text-right font-medium">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {schedules.map((s) => (
                    <tr
                      key={s.id}
                      className="group border-b border-border/60 last:border-0 hover:bg-muted/30 transition-colors"
                    >
                      <td className="px-4 py-3 align-middle font-medium text-foreground">
                        {s.name}
                      </td>
                      <td className="px-4 py-3 align-middle">
                        <Badge variant="outline" className="capitalize">
                          {s.interval}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 align-middle max-w-xs truncate mono text-xs text-muted-foreground">
                        {s.targets.join(", ")}
                      </td>
                      <td className="px-4 py-3 align-middle text-xs text-muted-foreground">
                        {s.last_run
                          ? new Date(s.last_run).toLocaleString()
                          : "Never"}
                      </td>
                      <td className="px-4 py-3 align-middle text-xs font-medium text-foreground">
                        {s.enabled
                          ? new Date(s.next_run).toLocaleString()
                          : "Paused"}
                      </td>
                      <td className="px-4 py-3 align-middle">
                        <Switch
                          checked={s.enabled}
                          onCheckedChange={(checked) =>
                            void handleToggleEnabled(s, checked)
                          }
                        />
                      </td>
                      <td className="px-4 py-3 align-middle text-right">
                        <ScheduleActionMenu
                          schedule={s}
                          onTrigger={() => void handleTrigger(s)}
                          onEdit={() => handleEditSchedule(s)}
                          onDelete={() => void handleDelete(s)}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editingSchedule ? "Edit Schedule" : "New Scan Schedule"}
            </DialogTitle>
            <DialogDescription>
              Configure the schedule frequency, target list, and scanning
              preferences.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={onSubmit} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="sched-name">Schedule Name *</Label>
                <Input
                  id="sched-name"
                  required
                  placeholder="e.g. Weekly Perimeter Audit"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="sched-interval">Frequency Interval *</Label>
                <Select value={interval} onValueChange={setInterval}>
                  <SelectTrigger id="sched-interval">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="hourly">Hourly</SelectItem>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sched-targets">Targets *</Label>
              <Textarea
                id="sched-targets"
                required
                rows={4}
                placeholder="example.com&#10;api.example.com"
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground">
                One target per line, or comma-separated. Only targets you are
                authorized to audit.
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>Scan Mode</Label>
                <Select value={scanMode} onValueChange={setScanMode}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="single">Single target</SelectItem>
                    <SelectItem value="wildcard">Wildcard / multi</SelectItem>
                    <SelectItem value="dast">DAST</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Provider profile</Label>
                <Select
                  value={providerProfile || "default"}
                  onValueChange={(v) =>
                    setProviderProfile(v === "default" ? "" : v)
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="default">Server default</SelectItem>
                    {profileOptions.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-[11px] text-muted-foreground">
                  Pick a stored credential profile to run this schedule
                  under. Manage profiles under Settings → Providers.
                </p>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>Recon Access</Label>
                <Select
                  value={reconMode}
                  onValueChange={(v) => setReconMode(v as ActivityMode)}
                  disabled={scanIntensity === "passive"}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active allowed</SelectItem>
                    <SelectItem value="passive">Passive only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Testing Access</Label>
                <Select
                  value={scanIntensity}
                  onValueChange={(v) => {
                    const next = v as ActivityMode;
                    setScanIntensity(next);
                    if (next === "passive") setReconMode("passive");
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active allowed</SelectItem>
                    <SelectItem value="passive">Passive only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sched-instruction">
                Custom instruction (optional)
              </Label>
              <Input
                id="sched-instruction"
                placeholder="e.g. Skip noisy subdomain enumeration, focus on api testing"
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="sched-model">Model override</Label>
              <Input
                id="sched-model"
                placeholder={llmQuery.data?.model || "model-name"}
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
              <p className="text-[11px] text-muted-foreground">
                Override the model for this schedule. Leave blank to use the
                server default{llmQuery.data?.model ? ` (${llmQuery.data.model})` : ""}.
              </p>
            </div>

            <Separator />

            <div className="space-y-2">
              <Label>Severity filter</Label>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map((s) => {
                  const active = severityFilter.includes(s);
                  return (
                    <button
                      type="button"
                      key={s}
                      onClick={() => toggleSeverity(s)}
                      className={cn(
                        "rounded-full border px-2.5 py-1 text-[11px] capitalize transition-colors",
                        active
                          ? "border-primary/60 bg-primary/10 text-foreground"
                          : "border-border bg-card text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {s}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] text-muted-foreground">
                Report only findings at or above selected severities. Leave
                blank for all.
              </p>
            </div>

            <Separator />

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="sched-company">Branding Company Name</Label>
                <Input
                  id="sched-company"
                  placeholder="Shown on the PDF cover page"
                  value={companyName}
                  onChange={(e) => setCompanyName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="sched-webhook">
                  Discord Webhook Notification
                </Label>
                <Input
                  id="sched-webhook"
                  placeholder="https://discord.com/api/webhooks/..."
                  value={discordWebhook}
                  onChange={(e) => setDiscordWebhook(e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Target Brand Logo</Label>
              <div className="flex items-center gap-3">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center overflow-hidden rounded-md border border-border bg-muted">
                  {logoPath ? (
                    <img
                      src={logoPath}
                      alt=""
                      className="h-full w-full object-contain"
                    />
                  ) : (
                    <ImageIcon className="h-5 w-5 text-muted-foreground" />
                  )}
                </div>
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex items-center gap-2">
                    <label
                      htmlFor="scheduleLogo"
                      className={cn(
                        "inline-flex h-8 cursor-pointer items-center justify-center gap-2 rounded-md border border-border bg-transparent px-3 text-xs font-medium transition-colors hover:bg-accent",
                        logoUploading && "pointer-events-none opacity-60",
                      )}
                    >
                      {logoUploading ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Upload className="h-3.5 w-3.5" />
                      )}
                      Upload
                    </label>
                    <Input
                      id="scheduleLogo"
                      type="file"
                      accept="image/png,image/jpeg"
                      disabled={logoUploading}
                      className="hidden"
                      onChange={(e) => {
                        void uploadReportLogo(e.currentTarget.files?.[0]);
                        e.currentTarget.value = "";
                      }}
                    />
                    {logoPath && (
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        onClick={() => {
                          setLogoPath("");
                          setLogoFileName("");
                        }}
                        aria-label="Remove logo"
                      >
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                  {logoFileName && (
                    <p className="truncate text-[11px] text-muted-foreground">
                      {logoFileName}
                    </p>
                  )}
                </div>
              </div>
            </div>

            {formError && (
              <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                {formError}
              </div>
            )}

            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={
                  createMutation.isPending ||
                  updateMutation.isPending ||
                  !targetsText.trim()
                }
              >
                {createMutation.isPending || updateMutation.isPending
                  ? "Saving…"
                  : "Save schedule"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Inline toggle switch component
function Switch({
  checked,
  onCheckedChange,
}: {
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
}) {
  return (
    <label className="inline-flex cursor-pointer items-center">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onCheckedChange(e.target.checked)}
        className="sr-only"
      />
      <div
        className={cn(
          "relative h-5 w-9 rounded-full transition-colors focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2",
          checked ? "bg-primary" : "bg-muted",
        )}
      >
        <div
          className={cn(
            "absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-background transition-transform shadow-sm",
            checked ? "translate-x-4" : "translate-x-0",
          )}
        />
      </div>
    </label>
  );
}

// Action dropdown menu for each row
function ScheduleActionMenu({
  schedule,
  onTrigger,
  onEdit,
  onDelete,
}: {
  schedule: ScanSchedule;
  onTrigger: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button
          size="icon"
          variant="ghost"
          aria-label={`Actions for schedule ${schedule.name}`}
        >
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className={menuContentClass}>
          <DropdownMenu.Item className={menuItemClass} onSelect={onTrigger}>
            <Play className="h-3.5 w-3.5 text-green-400" />
            Run now
          </DropdownMenu.Item>
          <DropdownMenu.Item className={menuItemClass} onSelect={onEdit}>
            <Edit2 className="h-3.5 w-3.5" />
            Edit settings
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            className={cn(menuItemClass, "text-red-400 focus:text-red-300")}
            onSelect={onDelete}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete schedule
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function ScheduleListSkeleton() {
  return (
    <Card>
      <CardContent className="space-y-2 p-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </CardContent>
    </Card>
  );
}
