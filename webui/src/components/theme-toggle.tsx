import { Check, Monitor, Moon, Sun, type LucideIcon } from "lucide-react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { cn } from "@/lib/utils";
import { useI18n } from "@/i18n";
import { useTheme, type ThemeMode } from "@/store/theme";

// Compact theme picker for the topbar. Switches between light, dark, and system
// (follows the OS) immediately, persisted to localStorage. Mirrors the
// language-switcher styling so the two controls sit together consistently.
export function ThemeToggle() {
  const { mode, resolved, setTheme } = useTheme();
  const { t } = useI18n();

  const options: { value: ThemeMode; label: string; icon: LucideIcon }[] = [
    { value: "light", label: t("theme.light"), icon: Sun },
    { value: "dark", label: t("theme.dark"), icon: Moon },
    { value: "system", label: t("theme.system"), icon: Monitor },
  ];

  // The trigger shows what's actually rendered: the OS-resolved icon in system
  // mode, otherwise the chosen mode's icon.
  const TriggerIcon = mode === "system" ? Monitor : resolved === "dark" ? Moon : Sun;

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-card text-muted-foreground transition-colors hover:text-foreground"
          aria-label={t("topbar.theme")}
          title={t("topbar.theme")}
        >
          <TriggerIcon className="h-3.5 w-3.5" aria-hidden />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          className="z-50 min-w-40 overflow-hidden rounded-md border border-border bg-card p-1 text-sm shadow-md"
        >
          <DropdownMenu.Label className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
            {t("topbar.theme")}
          </DropdownMenu.Label>
          {options.map((o) => {
            const Icon = o.icon;
            return (
              <DropdownMenu.Item
                key={o.value}
                onSelect={() => setTheme(o.value)}
                className={cn(
                  "flex cursor-pointer items-center justify-between gap-2 rounded-sm px-2 py-1.5 outline-none transition-colors",
                  "hover:bg-accent/40 focus:bg-accent/40",
                  o.value === mode ? "text-foreground" : "text-muted-foreground",
                )}
              >
                <span className="flex items-center gap-2">
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                  {o.label}
                </span>
                {o.value === mode && <Check className="h-3.5 w-3.5" aria-hidden />}
              </DropdownMenu.Item>
            );
          })}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
