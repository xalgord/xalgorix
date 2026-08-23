import { useMemo, useRef, useState, useEffect } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { ChevronRight, Download, FileText, Pause, Play, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, menuContentClass, menuItemClass as menuItemBase } from "@/lib/utils";
import { useWSStore, type FeedEvent } from "@/store/ws";
import { exportFeedEvents, type FeedExportFormat } from "@/lib/feed-export";
import { EmptyState } from "./states";

export type FeedFilter =
  | "all"
  | "tools"
  | "findings"
  | "errors"
  | "agent"
  | "http"
  | "llm";

const FILTERS: { key: FeedFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "tools", label: "Tools" },
  { key: "findings", label: "Findings" },
  { key: "errors", label: "Errors" },
  { key: "agent", label: "Agent" },
  { key: "http", label: "HTTP" },
  { key: "llm", label: "LLM" },
];

function matchFilter(e: FeedEvent, f: FeedFilter): boolean {
  const t = e.type || "";
  if (t === "thinking" || t === "thought") return false;
  if (f === "all") return true;
  switch (f) {
    case "tools":
      return (
        t === "tool_call" ||
        t === "tool_result" ||
        t === "tool_output" ||
        t === "tool_error" ||
        !!e.tool_name
      );
    case "findings":
      return (
        t === "vuln" ||
        t === "vuln_found" ||
        t === "vulns" ||
        (Array.isArray(e.vulns) && e.vulns.length > 0)
      );
    case "errors":
      return t === "error" || !!e.error;
    case "agent":
      return (
        t === "agent" ||
        t === "thought" ||
        t === "decision" ||
        t === "message" ||
        t === "phase"
      );
    case "http":
      return t === "http" || t === "request" || t === "response";
    case "llm":
      return t === "llm" || t === "token" || t === "llm_output";
    default:
      if (isInternalLLMInstruction(e.content || e.error || e.output)) {
        return false;
      }
      return true;
  }
}

function isInternalLLMInstruction(text?: string | null): boolean {
  if (!text) return false;
  const t = text.toLowerCase();
  return (
    t.includes("authorization reminder") ||
    t.includes("do not call") ||
    t.includes("your next tool call must") ||
    t.includes("must use tools") ||
    t.includes("repeated call:") ||
    t.includes("no progress:") ||
    t.includes("pivot required:") ||
    t.includes("force finishing") ||
    t.includes("loop limit reached") ||
    t.includes("consecutive responses with no tool call") ||
    t.includes("consecutive empty responses")
  );
}

// Event-type label colors. Base shades are darkened so the mono uppercase tags
// stay legible on the light surface; dark: variants restore the original bright
// shades tuned for the dark feed.
const TYPE_COLOR: Record<string, string> = {
  error: "text-red-600 dark:text-red-400",
  vuln: "text-orange-600 dark:text-orange-400",
  vuln_found: "text-orange-600 dark:text-orange-400",
  vulns: "text-orange-600 dark:text-orange-400",
  tool_call: "text-blue-600 dark:text-blue-300",
  tool_result: "text-emerald-600 dark:text-emerald-400",
  tool_error: "text-red-600 dark:text-red-400",
  tool_output: "text-neutral-600 dark:text-neutral-300",
  agent: "text-foreground",
  thought: "text-violet-600 dark:text-violet-300",
  decision: "text-violet-600 dark:text-violet-300",
  phase: "text-amber-700 dark:text-amber-300",
  llm: "text-cyan-700 dark:text-cyan-300",
  http: "text-sky-600 dark:text-sky-300",
  target_started: "text-emerald-600 dark:text-emerald-400",
  target_completed: "text-emerald-600 dark:text-emerald-400",
  queue_started: "text-emerald-600 dark:text-emerald-400",
  queue_finished: "text-emerald-600 dark:text-emerald-400",
  stopped: "text-red-600 dark:text-red-300",
  report_ready: "text-emerald-600 dark:text-emerald-400",
  paused: "text-amber-700 dark:text-amber-300",
  resumed: "text-emerald-600 dark:text-emerald-300",
  instance_started: "text-emerald-600 dark:text-emerald-300",
  instance_updated: "text-neutral-600 dark:text-neutral-400",
};

export function LiveEventRow({ event }: { event: FeedEvent }) {
  const [open, setOpen] = useState(false);
  const message = event.content || event.output || event.error || event.tool_name || event.type;
  const hasDetails =
    !!event.output ||
    !!event.tool_args ||
    !!event.error ||
    (event.vulns && event.vulns.length > 0);
  const ts = event.timestamp
    ? new Date(event.timestamp).toLocaleTimeString()
    : new Date(event._receivedAt).toLocaleTimeString();
  const colorCls = TYPE_COLOR[event.type] || "text-neutral-600 dark:text-neutral-300";

  return (
    <div className="group border-b border-border last:border-0">
      <button
        type="button"
        onClick={() => hasDetails && setOpen((v) => !v)}
        className={cn(
          "flex w-full items-start gap-3 px-3 py-2 text-left transition-colors",
          hasDetails && "hover:bg-accent/40",
        )}
      >
        <span className="mt-0.5 text-[11px] text-muted-foreground tabular-nums mono w-20 shrink-0">
          {ts}
        </span>
        <span
          className={cn(
            "mt-0.5 text-[10px] uppercase tracking-wide font-medium w-24 shrink-0 mono",
            colorCls,
          )}
        >
          {event.type || "event"}
        </span>
        {event.tool_name && (
          <span className="mt-0.5 text-[10px] text-muted-foreground mono w-32 shrink-0 truncate">
            {event.tool_name}
          </span>
        )}
        <span className="flex-1 min-w-0 text-xs text-foreground/90 truncate mono">
          {message}
        </span>
        {hasDetails && (
          <ChevronRight
            className={cn(
              "mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
              open && "rotate-90",
            )}
          />
        )}
      </button>
      {open && hasDetails && (
        <div className="px-3 pb-3 -mt-1 ml-[7.5rem] space-y-2">
          {event.error && (
            <pre className="rounded border border-red-500/30 bg-red-500/5 p-2 text-[11px] mono text-red-700 dark:text-red-300 whitespace-pre-wrap break-words">
              {event.error}
            </pre>
          )}
          {event.tool_args && Object.keys(event.tool_args).length > 0 && (
            <pre className="rounded border border-border bg-muted/40 p-2 text-[11px] mono whitespace-pre-wrap break-words">
              {JSON.stringify(event.tool_args, null, 2)}
            </pre>
          )}
          {event.output && (
            <pre className="rounded border border-border bg-muted/40 p-2 text-[11px] mono whitespace-pre-wrap break-words max-h-72 overflow-auto">
              {event.output}
            </pre>
          )}
          {event.vulns && event.vulns.length > 0 && (
            <pre className="rounded border border-border bg-muted/40 p-2 text-[11px] mono whitespace-pre-wrap break-words max-h-72 overflow-auto">
              {JSON.stringify(event.vulns, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export function LiveFeed({
  events,
  filter,
  onFilterChange,
  emptyTitle = "No events yet",
  emptyDescription = "Events will appear here as soon as a scan produces output.",
  autoScroll = true,
  showControls = true,
  className,
  onClearEvents,
  exportFilePrefix,
  exportScope,
}: {
  events: FeedEvent[];
  filter: FeedFilter;
  onFilterChange: (f: FeedFilter) => void;
  emptyTitle?: string;
  emptyDescription?: string;
  autoScroll?: boolean;
  showControls?: boolean;
  className?: string;
  onClearEvents?: () => void;
  exportFilePrefix?: string;
  exportScope?: string;
}) {
  const paused = useWSStore((s) => s.paused);
  const setPaused = useWSStore((s) => s.setPaused);
  const clearEvents = useWSStore((s) => s.clearEvents);
  const scrollRef = useRef<HTMLDivElement>(null);

  const visible = useMemo(
    () => events.filter((e) => matchFilter(e, filter)),
    [events, filter],
  );

  function handleExport(format: FeedExportFormat) {
    exportFeedEvents({
      events: visible,
      format,
      filenamePrefix: exportFilePrefix,
      metadata: {
        filter,
        scope: exportScope,
        total_events: events.length,
        visible_events: visible.length,
      },
    });
  }

  useEffect(() => {
    if (autoScroll && !paused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [visible.length, autoScroll, paused]);

  return (
    <div className={cn("rounded-md border border-border bg-card", className)}>
      {showControls && (
        <div className="flex flex-wrap items-center gap-1 border-b border-border px-2 py-1.5">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              type="button"
              onClick={() => onFilterChange(f.key)}
              className={cn(
                "rounded-sm px-2 py-1 text-xs transition-colors",
                filter === f.key
                  ? "bg-accent text-accent-foreground"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent/40",
              )}
            >
              {f.label}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-1">
            <FeedExportMenu
              disabled={visible.length === 0}
              visibleCount={visible.length}
              onExport={handleExport}
            />
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setPaused(!paused)}
              className="h-7 px-2"
            >
              {paused ? (
                <>
                  <Play className="h-3.5 w-3.5" /> Resume
                </>
              ) : (
                <>
                  <Pause className="h-3.5 w-3.5" /> Pause
                </>
              )}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={onClearEvents ?? clearEvents}
              className="h-7 px-2"
            >
              <Trash2 className="h-3.5 w-3.5" /> Clear
            </Button>
          </div>
        </div>
      )}
      <div
        ref={scrollRef}
        className="max-h-[60vh] min-h-64 overflow-auto bg-background/40"
      >
        {visible.length === 0 ? (
          <EmptyState
            title={emptyTitle}
            description={emptyDescription}
            className="m-3"
          />
        ) : (
          visible.map((e) => <LiveEventRow key={e._key} event={e} />)
        )}
      </div>
    </div>
  );
}

const menuItemClass =
  cn(menuItemBase, "data-[disabled]:pointer-events-none data-[disabled]:opacity-50");

function FeedExportMenu({
  disabled,
  visibleCount,
  onExport,
}: {
  disabled: boolean;
  visibleCount: number;
  onExport: (format: FeedExportFormat) => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button
          size="sm"
          variant="ghost"
          disabled={disabled}
          className="h-7 px-2"
          aria-label={`Export ${visibleCount} live feed events`}
        >
          <Download className="h-3.5 w-3.5" /> Export
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className={menuContentClass}>
          <DropdownMenu.Label className="px-2 py-1.5 text-xs text-muted-foreground">
            {visibleCount} visible events
          </DropdownMenu.Label>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            className={menuItemClass}
            onSelect={() => onExport("json")}
          >
            <Download className="h-3.5 w-3.5" />
            JSON
          </DropdownMenu.Item>
          <DropdownMenu.Item
            className={menuItemClass}
            onSelect={() => onExport("jsonl")}
          >
            <Download className="h-3.5 w-3.5" />
            JSONL
          </DropdownMenu.Item>
          <DropdownMenu.Item
            className={menuItemClass}
            onSelect={() => onExport("txt")}
          >
            <FileText className="h-3.5 w-3.5" />
            Transcript
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
