// Lightweight theme store for the dashboard UI.
//
// Mirrors the i18n store (src/i18n/index.ts): a tiny useSyncExternalStore-based
// store so any component can read/set the theme without a context provider. The
// choice is persisted to localStorage and mirrored onto <html> as the `dark`
// class (class-based dark mode; see the @custom-variant in styles.css) plus the
// `theme-color` meta tag.
//
// Modes: "light" | "dark" | "system". "system" follows the OS
// prefers-color-scheme and updates live when it changes. The pre-hydration
// inline script in index.html applies the same class synchronously to avoid a
// flash of the wrong theme before this module loads.

import { useSyncExternalStore } from "react";

export type ThemeMode = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "xalgorix.theme";

// Kept in sync with --background in styles.css so the mobile browser chrome
// matches the app surface.
const THEME_COLOR: Record<ResolvedTheme, string> = {
  light: "#ffffff",
  dark: "#050505",
};

function isThemeMode(v: unknown): v is ThemeMode {
  return v === "light" || v === "dark" || v === "system";
}

function readStoredMode(): ThemeMode {
  if (typeof window === "undefined") return "dark";
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    return isThemeMode(v) ? v : "dark";
  } catch {
    return "dark";
  }
}

function systemPrefersDark(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return true;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function resolveMode(mode: ThemeMode): ResolvedTheme {
  if (mode === "system") return systemPrefersDark() ? "dark" : "light";
  return mode;
}

let currentMode: ThemeMode = readStoredMode();
let currentResolved: ResolvedTheme = resolveMode(currentMode);
const listeners = new Set<() => void>();

function applyResolved(resolved: ResolvedTheme) {
  if (typeof document === "undefined") return;
  document.documentElement.classList.toggle("dark", resolved === "dark");
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", THEME_COLOR[resolved]);
}
applyResolved(currentResolved);

// While in "system" mode, follow live OS theme changes.
if (typeof window !== "undefined" && window.matchMedia) {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const onChange = () => {
    if (currentMode !== "system") return;
    const next: ResolvedTheme = systemPrefersDark() ? "dark" : "light";
    if (next === currentResolved) return;
    currentResolved = next;
    applyResolved(next);
    emit();
  };
  if (mq.addEventListener) mq.addEventListener("change", onChange);
  else if (mq.addListener) mq.addListener(onChange); // older Safari
}

function emit() {
  for (const listener of listeners) listener();
}

/** Set the active theme mode. Persists and applies immediately. */
export function setTheme(mode: ThemeMode) {
  currentMode = mode;
  try {
    window.localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    /* storage may be unavailable (private mode); UI still switches */
  }
  const resolved = resolveMode(mode);
  currentResolved = resolved;
  applyResolved(resolved);
  emit();
}

export function getThemeMode(): ThemeMode {
  return currentMode;
}

export function getResolvedTheme(): ResolvedTheme {
  return currentResolved;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export interface ThemeState {
  mode: ThemeMode;
  resolved: ResolvedTheme;
  setTheme: (mode: ThemeMode) => void;
}

/** React hook exposing the active theme mode, its resolved value, and a setter. */
export function useTheme(): ThemeState {
  const mode = useSyncExternalStore(subscribe, getThemeMode, () => "dark" as ThemeMode);
  const resolved = useSyncExternalStore(
    subscribe,
    getResolvedTheme,
    () => "dark" as ResolvedTheme,
  );
  return { mode, resolved, setTheme };
}
