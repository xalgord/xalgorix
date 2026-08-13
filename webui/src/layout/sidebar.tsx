import { NavLink } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  Clock,
  FileText,
  LayoutGrid,
  Mail,
  Plug,
  Plus,
  Radio,
  Server,
  Settings,
  ShieldAlert,
  Star,
  Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useVersion } from "@/api/queries";
import { useI18n } from "@/i18n";

const GITHUB_REPO = "xalgord/xalgorix";

const NAV: { to: string; labelKey: string; icon: typeof LayoutGrid; end?: boolean }[] = [
  { to: "/", labelKey: "nav.overview", icon: LayoutGrid, end: true },
  { to: "/scans/new", labelKey: "nav.newScan", icon: Plus },
  { to: "/scans", labelKey: "nav.scans", icon: Target },
  { to: "/schedules", labelKey: "nav.schedules", icon: Clock },
  { to: "/instances", labelKey: "nav.instances", icon: Server },
  { to: "/findings", labelKey: "nav.findings", icon: ShieldAlert },
  { to: "/live", labelKey: "nav.live", icon: Radio },
  { to: "/email", labelKey: "nav.email", icon: Mail },
  { to: "/reports", labelKey: "nav.reports", icon: FileText },
  { to: "/integrations", labelKey: "nav.integrations", icon: Plug },
  { to: "/settings", labelKey: "nav.settings", icon: Settings },
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useI18n();
  const { data: version } = useVersion();
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-card">
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <div className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-md border border-border bg-background">
          <img src="/logo.png" alt="" className="h-full w-full object-cover" aria-hidden />
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold tracking-tight">Xalgorix</span>
          <span className="text-[10px] text-muted-foreground mono">
            {version?.version ? `v${version.version}` : t("sidebar.securityScanner")}
          </span>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto py-3" aria-label="Primary">
        <ul className="space-y-0.5 px-2">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                      isActive
                        ? "bg-accent text-accent-foreground"
                        : "text-muted-foreground hover:bg-accent/40 hover:text-foreground",
                    )
                  }
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                  <span>{t(item.labelKey)}</span>
                </NavLink>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="px-2 pb-2 pt-1">
        <a
          href={`https://github.com/${GITHUB_REPO}`}
          target="_blank"
          rel="noreferrer"
          onClick={onNavigate}
          className="group flex items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:border-amber-400/50 hover:text-foreground"
          title={t("sidebar.githubTitle")}
        >
          <svg viewBox="0 0 16 16" className="h-4 w-4" fill="currentColor" aria-hidden>
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 012-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z" />
          </svg>
          <span>{t("sidebar.github")}</span>
          <Star
            className="h-4 w-4 text-amber-400 transition-transform group-hover:scale-110"
            aria-hidden
          />
        </a>
      </div>
      <div className="border-t border-border px-4 py-3 text-[10px] text-muted-foreground mono">
        <div className="flex items-center gap-1.5">
          <Activity className="h-3 w-3" aria-hidden />
          <span>{t("sidebar.localScanner")}</span>
        </div>
        <div className="mt-1 flex items-center gap-1.5 opacity-70">
          <AlertOctagon className="h-3 w-3" aria-hidden />
          <span>{t("sidebar.commandHint")}</span>
        </div>
      </div>
    </aside>
  );
}
