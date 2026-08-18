import { Check, Globe } from "lucide-react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { cn } from "@/lib/utils";
import { useI18n, LANGUAGES } from "@/i18n";

// Compact language picker for the topbar. Switches the dashboard UI language
// immediately (client-side, persisted to localStorage). The AI output language
// is a separate server setting (XALGORIX_LANGUAGE) configurable under
// Settings → Environment.
export function LanguageSwitcher() {
  const { lang, setLanguage, t } = useI18n();
  const active = LANGUAGES.find((l) => l.code === lang) ?? LANGUAGES[0];

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-md border border-border bg-card px-2 text-xs text-muted-foreground transition-colors hover:text-foreground"
          aria-label={t("topbar.language")}
          title={t("topbar.language")}
        >
          <Globe className="h-3.5 w-3.5" aria-hidden />
          <span className="hidden sm:inline">{active.nativeLabel}</span>
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          className="z-50 min-w-40 overflow-hidden rounded-md border border-border bg-card p-1 text-sm shadow-md"
        >
          <DropdownMenu.Label className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
            {t("topbar.language")}
          </DropdownMenu.Label>
          {LANGUAGES.map((l) => (
            <DropdownMenu.Item
              key={l.code}
              onSelect={() => setLanguage(l.code)}
              className={cn(
                "flex cursor-pointer items-center justify-between gap-2 rounded-sm px-2 py-1.5 outline-none transition-colors",
                "hover:bg-accent/40 focus:bg-accent/40",
                l.code === lang ? "text-foreground" : "text-muted-foreground",
              )}
            >
              <span>{l.nativeLabel}</span>
              {l.code === lang && <Check className="h-3.5 w-3.5" aria-hidden />}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
