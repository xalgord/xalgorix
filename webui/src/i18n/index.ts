// Lightweight i18n store for the dashboard UI.
//
// Uses zustand (already a dependency) so any component can read the active
// language and the `t()` helper without prop-drilling or a context provider.
// The chosen language is persisted to localStorage and mirrored onto
// <html lang> so the browser and assistive tech pick up the change.
//
// This governs the DASHBOARD CHROME only. AI-generated output (findings,
// report prose, agent/chat replies) is localized server-side via the
// XALGORIX_LANGUAGE backend setting; see internal/config/language.go.

import { useSyncExternalStore } from "react";
import {
  DEFAULT_LANGUAGE,
  normalizeLanguage,
  translations,
  type LanguageCode,
} from "./translations";

const STORAGE_KEY = "xalgorix.lang";

function readStoredLanguage(): LanguageCode {
  if (typeof window === "undefined") return DEFAULT_LANGUAGE;
  try {
    return normalizeLanguage(window.localStorage.getItem(STORAGE_KEY));
  } catch {
    return DEFAULT_LANGUAGE;
  }
}

let currentLanguage: LanguageCode = readStoredLanguage();
const listeners = new Set<() => void>();

function applyHtmlLang(lang: LanguageCode) {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("lang", lang);
  }
}
applyHtmlLang(currentLanguage);

function emit() {
  for (const listener of listeners) listener();
}

/** Change the active UI language. No-op when the value is unchanged. */
export function setLanguage(raw: string | LanguageCode) {
  const next = normalizeLanguage(raw);
  if (next === currentLanguage) return;
  currentLanguage = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    /* storage may be unavailable (private mode); UI still switches */
  }
  applyHtmlLang(next);
  emit();
}

/**
 * Adopt a server-provided default language when the user has never made an
 * explicit choice in this browser. Lets a fresh dashboard honor the operator's
 * XALGORIX_LANGUAGE setting without overriding a local preference.
 */
export function syncLanguageFromServer(raw: string | null | undefined) {
  if (typeof window === "undefined") return;
  try {
    if (window.localStorage.getItem(STORAGE_KEY)) return; // explicit choice wins
  } catch {
    return;
  }
  const next = normalizeLanguage(raw);
  if (next === currentLanguage) return;
  currentLanguage = next;
  applyHtmlLang(next);
  emit();
}

export function getLanguage(): LanguageCode {
  return currentLanguage;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Translate a key for a specific language, with graceful fallback. */
export function translate(lang: LanguageCode, key: string): string {
  return translations[lang]?.[key] ?? translations[DEFAULT_LANGUAGE][key] ?? key;
}

export interface I18n {
  lang: LanguageCode;
  t: (key: string) => string;
  setLanguage: (raw: string | LanguageCode) => void;
}

/** React hook exposing the active language and a bound `t()` translator. */
export function useI18n(): I18n {
  const lang = useSyncExternalStore(subscribe, getLanguage, () => DEFAULT_LANGUAGE);
  return {
    lang,
    t: (key: string) => translate(lang, key),
    setLanguage,
  };
}

export { DEFAULT_LANGUAGE, normalizeLanguage } from "./translations";
export type { LanguageCode } from "./translations";
export { LANGUAGES } from "./translations";
