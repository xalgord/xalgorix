import { useNavigate } from "react-router-dom";
import { useMemo, useState, type FormEvent } from "react";
import {
  ChevronLeft,
  FileText,
  ImageIcon,
  Loader2,
  Play,
  Radar,
  Save,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { PHASES } from "@/components/phase-progress";
import { api } from "@/api/client";
import { useAuthProfiles, useLLMSettings, useProviders, useStartScan } from "@/api/queries";
import { cn } from "@/lib/utils";

const SCAN_MODES = [
  {
    value: "single",
    label: "Single target",
    hint: "Test exactly what you provided. No subdomain enumeration.",
  },
  {
    value: "wildcard",
    label: "Wildcard / multi",
    hint: "Enumerate subdomains, then scan each one.",
  },
  {
    value: "dast",
    label: "DAST",
    hint: "Authenticated app testing with browser-driven probes.",
  },
];

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
type ActivityMode = "active" | "passive";

const ACTIVITY_OPTIONS: Array<{
  value: ActivityMode;
  label: string;
  hint: string;
}> = [
  {
    value: "passive",
    label: "Passive only",
    hint: "Public sources and existing evidence. No direct target requests.",
  },
  {
    value: "active",
    label: "Active allowed",
    hint: "Direct in-scope probes and verification are allowed.",
  },
];

export default function NewScanPage() {
  const nav = useNavigate();
  const startScan = useStartScan();
  const llmQuery = useLLMSettings();

  const [targetsText, setTargetsText] = useState("");
  const [name, setName] = useState("");
  const [scanMode, setScanMode] = useState("single");
  const [reconMode, setReconMode] = useState<ActivityMode>("active");
  const [scanIntensity, setScanIntensity] = useState<ActivityMode>("active");
  const [instruction, setInstruction] = useState("");
  const [selectedPhases, setSelectedPhases] = useState<number[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [model, setModel] = useState("");
  // Optional "<provider>:<profileId>" key naming a stored AuthProfile
  // (provider-catalog-and-oauth, R11.1, R14.4). Empty string ("default"
  // option) means "let the server pick" — don't send provider_profile
  // and the legacy / catalog-default path resolves the credentials.
  const [providerProfile, setProviderProfile] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [logoPath, setLogoPath] = useState("");
  const [logoFileName, setLogoFileName] = useState("");
  const [logoUploading, setLogoUploading] = useState(false);
  const [contextPath, setContextPath] = useState("");
  const [contextInfo, setContextInfo] = useState<string>("");
  const [contextUploading, setContextUploading] = useState(false);
  const [targetAuth, setTargetAuth] = useState("");
  const [targetAuthB, setTargetAuthB] = useState("");
  const [error, setError] = useState<string | null>(null);

  const targets = useMemo(
    () =>
      targetsText
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean),
    [targetsText],
  );

  // Profile picker source. Profiles drive the picker; the catalog
  // (separate query) supplies the human-readable displayName per
  // entry. Both queries fail open: when neither has loaded yet (or
  // the user has no profiles configured) the picker collapses to
  // the single "Server default" option.
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

  function togglePhase(id: number) {
    setSelectedPhases((cur) =>
      cur.includes(id)
        ? cur.filter((p) => p !== id)
        : [...cur, id].sort((a, b) => a - b),
    );
  }
  function toggleSeverity(s: string) {
    setSeverityFilter((cur) =>
      cur.includes(s) ? cur.filter((p) => p !== s) : [...cur, s],
    );
  }
  function updateScanIntensity(value: ActivityMode) {
    setScanIntensity(value);
    if (value === "passive") setReconMode("passive");
  }

  async function uploadReportLogo(file?: File) {
    if (!file) return;
    setError(null);
    if (!/\.(png|jpe?g)$/i.test(file.name)) {
      setError("Report logos must be PNG or JPEG.");
      return;
    }
    setLogoUploading(true);
    try {
      const res = await api.uploadLogo(file);
      setLogoPath(res.path);
      setLogoFileName(res.filename || file.name);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload logo");
    } finally {
      setLogoUploading(false);
    }
  }

  async function uploadScanContext(file?: File) {
    if (!file) return;
    setError(null);
    if (!/\.(json|ya?ml|har|xml|apk|txt)$/i.test(file.name)) {
      setError("Context must be an OpenAPI/Swagger spec, HAR, Postman collection, Burp export, or Android APK (.json, .yaml, .yml, .har, .xml, .apk).");
      return;
    }
    setContextUploading(true);
    try {
      const res = await api.uploadContext(file);
      setContextPath(res.path);
      const fmts = (res.formats || []).join(", ") || "context";
      setContextInfo(
        `${file.name} — ${res.endpoints} endpoint${res.endpoints === 1 ? "" : "s"} seeded (${fmts})${res.has_auth ? " · auth captured" : ""}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload context");
    } finally {
      setContextUploading(false);
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    await submitScan(false);
  }

  async function submitScan(saveOnly: boolean) {
    setError(null);
    if (!targets.length) {
      setError("At least one target is required.");
      return;
    }
    try {
      const res = await startScan.mutateAsync({
        targets,
        name: name.trim() || undefined,
        scan_mode: scanMode,
        instruction: instruction.trim() || undefined,
        phases: selectedPhases.length ? selectedPhases : undefined,
        recon_mode: reconMode,
        scan_intensity: scanIntensity,
        severity_filter: severityFilter.length ? severityFilter : undefined,
        model: model.trim() || undefined,
        provider_profile: providerProfile || undefined,
        company_name: companyName.trim() || undefined,
        logo_path: logoPath || undefined,
        scan_context: contextPath || undefined,
        target_auth: targetAuth.trim() || undefined,
        target_auth_b: targetAuthB.trim() || undefined,
        save_only: saveOnly || undefined,
      });
      const id =
        (res as { id?: string; instance_id?: string })?.instance_id ||
        (res as { id?: string })?.id;
      if (id) nav(`/scans/${id}`);
      else nav("/scans");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : saveOnly
            ? "Failed to save scan"
            : "Failed to start scan",
      );
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => nav(-1)}
          className="text-muted-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" /> Back
        </Button>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-balance">
          Start a new scan
        </h1>
        <p className="mt-1 text-sm text-muted-foreground text-pretty">
          Configure target, scope, and methodology phases. Xalgorix orchestrates
          recon and active probes, then synthesizes findings with the agent.
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-5">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Targets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="targets">Targets *</Label>
              <Textarea
                id="targets"
                required
                placeholder={"example.com\nhttps://app.example.com"}
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                rows={3}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground">
                One per line, or comma-separated. Domains, hosts, or URLs.
              </p>
              {targets.length > 1 && (
                <div className="flex flex-wrap gap-1">
                  {targets.map((t) => (
                    <Badge
                      key={t}
                      variant="outline"
                      className="mono text-[10px]"
                    >
                      {t}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="name">Display name (optional)</Label>
              <Input
                id="name"
                placeholder="Auto-generated from target if blank"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Security context (optional)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-[11px] text-muted-foreground text-pretty">
              Attach an <span className="font-medium text-foreground">OpenAPI/Swagger spec</span>,{" "}
              <span className="font-medium text-foreground">HAR capture</span>, or{" "}
              <span className="font-medium text-foreground">Postman collection</span>,{" "}
              <span className="font-medium text-foreground">Burp export</span>, or an{" "}
              <span className="font-medium text-foreground">Android APK</span>. Xalgorix
              seeds the scan with the target&apos;s real endpoints and parameters (and any captured
              session), so it tests the actual attack surface instead of relying on crawling. This
              is the single biggest boost to black-box coverage.
            </p>
            <div className="flex items-center gap-3">
              <label
                htmlFor="scanContext"
                className={cn(
                  "inline-flex h-8 cursor-pointer items-center justify-center gap-2 rounded-md border border-border bg-transparent px-3 text-xs font-medium transition-colors hover:bg-accent",
                  contextUploading && "pointer-events-none opacity-60",
                )}
              >
                {contextUploading ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Upload className="h-3.5 w-3.5" />
                )}
                Attach context
              </label>
              <Input
                id="scanContext"
                type="file"
                accept=".json,.yaml,.yml,.har,.xml,.apk,.txt"
                disabled={contextUploading}
                className="hidden"
                onChange={(e) => {
                  void uploadScanContext(e.currentTarget.files?.[0]);
                  e.currentTarget.value = "";
                }}
              />
              {contextPath && (
                <span className="inline-flex items-center gap-1.5 text-[11px] text-emerald-400">
                  <FileText className="h-3.5 w-3.5" />
                  {contextInfo}
                </span>
              )}
              {contextPath && (
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  onClick={() => {
                    setContextPath("");
                    setContextInfo("");
                  }}
                  aria-label="Remove attached context"
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Authenticated access (optional)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="targetAuth">Authenticated session</Label>
              <Textarea
                id="targetAuth"
                placeholder={"Cookie: session=abc123; Authorization: Bearer eyJ…"}
                value={targetAuth}
                onChange={(e) => setTargetAuth(e.target.value)}
                rows={2}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground text-pretty">
                Applied automatically to every request so the agent tests the post-login surface
                (IDOR/BOLA, privilege escalation, business logic). One{" "}
                <span className="mono">Header: value</span> per line, or semicolon-separated.
                Credentials are redacted from the event stream, logs, and reports.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="targetAuthB">Second account (for IDOR/BOLA proof)</Label>
              <Textarea
                id="targetAuthB"
                placeholder={"Cookie: session=DIFFERENT_USER…"}
                value={targetAuthB}
                onChange={(e) => setTargetAuthB(e.target.value)}
                rows={2}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground text-pretty">
                A DISTINCT second account. The agent uses it to prove horizontal access control —
                reaching account A&apos;s objects with account B&apos;s session confirms BOLA/IDOR
                with concrete evidence.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Target access</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Radar className="h-3.5 w-3.5 text-muted-foreground" />
                Recon phase
              </Label>
              <div className="grid gap-2">
                {ACTIVITY_OPTIONS.map((option) => {
                  const active = reconMode === option.value;
                  const disabled =
                    scanIntensity === "passive" && option.value === "active";
                  return (
                    <button
                      type="button"
                      key={option.value}
                      disabled={disabled}
                      onClick={() => setReconMode(option.value)}
                      className={cn(
                        "rounded-md border border-border bg-card p-3 text-left transition-colors",
                        "hover:border-foreground/30 disabled:cursor-not-allowed disabled:opacity-50",
                        active &&
                          "border-primary/70 bg-primary/5 ring-1 ring-primary/30",
                      )}
                    >
                      <div className="text-sm font-medium">{option.label}</div>
                      <p className="mt-1 text-[11px] text-muted-foreground text-pretty">
                        {option.hint}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground" />
                Testing phases
              </Label>
              <div className="grid gap-2">
                {ACTIVITY_OPTIONS.map((option) => {
                  const active = scanIntensity === option.value;
                  return (
                    <button
                      type="button"
                      key={option.value}
                      onClick={() => updateScanIntensity(option.value)}
                      className={cn(
                        "rounded-md border border-border bg-card p-3 text-left transition-colors",
                        "hover:border-foreground/30",
                        active &&
                          "border-primary/70 bg-primary/5 ring-1 ring-primary/30",
                      )}
                    >
                      <div className="text-sm font-medium">{option.label}</div>
                      <p className="mt-1 text-[11px] text-muted-foreground text-pretty">
                        {option.hint}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Report branding</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-[1fr_220px]">
            <div className="space-y-2">
              <Label htmlFor="companyName">Target brand name</Label>
              <Input
                id="companyName"
                placeholder="Shown on the PDF cover"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Target brand logo</Label>
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
                      htmlFor="reportLogo"
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
                      id="reportLogo"
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
                        aria-label="Remove report logo"
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scan mode</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-3">
              {SCAN_MODES.map((m) => (
                <button
                  type="button"
                  key={m.value}
                  onClick={() => setScanMode(m.value)}
                  className={cn(
                    "rounded-md border border-border bg-card p-3 text-left transition-colors",
                    "hover:border-foreground/30",
                    scanMode === m.value &&
                      "border-primary/70 bg-primary/5 ring-1 ring-primary/30",
                  )}
                >
                  <div className="text-sm font-medium">{m.label}</div>
                  <p className="mt-1 text-[11px] text-muted-foreground text-pretty">
                    {m.hint}
                  </p>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Methodology phases
              <span className="ml-2 text-[11px] font-normal text-muted-foreground">
                {selectedPhases.length
                  ? `${selectedPhases.length} selected`
                  : "all phases (default)"}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {PHASES.map((p) => {
                const active = selectedPhases.includes(p.id);
                return (
                  <button
                    type="button"
                    key={p.id}
                    onClick={() => togglePhase(p.id)}
                    className={cn(
                      "flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-left text-xs transition-colors",
                      "hover:border-foreground/30",
                      active &&
                        "border-primary/70 bg-primary/5 text-foreground",
                      !active && "text-muted-foreground",
                    )}
                  >
                    <span
                      className={cn(
                        "mono inline-flex h-5 w-7 shrink-0 items-center justify-center rounded text-[10px]",
                        active
                          ? "bg-primary/15 text-primary"
                          : "bg-muted text-muted-foreground",
                      )}
                    >
                      {String(p.id).padStart(2, "0")}
                    </span>
                    <span className="truncate">{p.name}</span>
                  </button>
                );
              })}
            </div>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => setSelectedPhases([])}
              >
                All phases
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => setSelectedPhases([1, 22])}
              >
                Recon + report only
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Refinement</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
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
            <div className="space-y-2">
              <Label htmlFor="instr">Custom instruction</Label>
              <Textarea
                id="instr"
                placeholder="e.g. Focus on the payment flow at /checkout and skip /static/."
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="model">Model override</Label>
              <Input
                id="model"
                placeholder={llmQuery.data?.model || "model-name"}
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
              <p className="text-[11px] text-muted-foreground">
                Override the model for this scan. Leave blank to use the
                server default{llmQuery.data?.model ? ` (${llmQuery.data.model})` : ""}.
              </p>
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
                Pick a stored credential profile to route this scan
                through. Manage profiles under Settings → Providers.
              </p>
            </div>
          </CardContent>
        </Card>

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="flex flex-col-reverse gap-2 border-t border-border pt-3 sm:flex-row sm:items-center sm:justify-end">
          <Button type="button" variant="outline" onClick={() => nav(-1)}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!targets.length || startScan.isPending}
            onClick={() => void submitScan(true)}
          >
            {startScan.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Save className="h-3.5 w-3.5" />
            )}
            Save for later
          </Button>
          <Button
            type="submit"
            disabled={!targets.length || startScan.isPending}
          >
            {startScan.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            Start scan
          </Button>
        </div>
      </form>
    </div>
  );
}
