import { Link } from "react-router-dom";
import {
  useDismissLegacyImport,
  useLegacyImportStatus,
} from "@/api/queries";

/**
 * One-time banner surfaced after the server has migrated scan records
 * from the pre-migration `~/xalgorix-data/` directory into the active
 * data dir. The count comes from `GET /api/legacy-import/status` which
 * exposes the in-memory counter populated by `importLegacyDataDir()`
 * at startup. Dismissal hits `POST /api/legacy-import/status` which
 * flips the in-memory `dismissed` flag for the remainder of the server
 * process; restart re-shows once.
 *
 * Suppressed when count == 0 (no work was done) or when the server
 * already reported `dismissed: true` (the user dismissed it earlier
 * in this process lifetime). See findings-consistency-and-pagination
 * spec, Property 6 (legacy-import idempotence).
 */
export function LegacyImportBanner() {
  const { data, isLoading } = useLegacyImportStatus();
  const dismiss = useDismissLegacyImport();

  if (isLoading || !data) return null;
  if (data.count === 0) return null;
  if (data.dismissed) return null;

  return (
    <div
      role="status"
      className="border-b border-emerald-500/30 bg-emerald-500/10 px-6 py-2 text-xs text-emerald-700 dark:text-emerald-200"
    >
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2">
        <span>
          Imported {data.count} legacy{" "}
          {data.count === 1 ? "scan" : "scans"} from{" "}
          <code className="rounded bg-emerald-500/10 px-1 py-0.5 font-mono">
            ~/xalgorix-data/
          </code>
          .{" "}
          <Link
            to="/findings"
            className="underline underline-offset-2 hover:text-emerald-800 dark:hover:text-emerald-100"
          >
            Click to review
          </Link>{" "}
          or dismiss.
        </span>
        <button
          type="button"
          onClick={() => dismiss.mutate()}
          disabled={dismiss.isPending}
          className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider text-emerald-700 dark:text-emerald-100 hover:bg-emerald-500/20 disabled:opacity-60"
          aria-label="Dismiss legacy import banner"
        >
          {dismiss.isPending ? "Dismissing…" : "Dismiss"}
        </button>
      </div>
    </div>
  );
}
