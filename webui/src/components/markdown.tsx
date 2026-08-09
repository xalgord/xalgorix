// Lightweight, dependency-free Markdown renderer for finding text (description,
// impact, technical analysis, remediation, …). The engine's LLM emits Markdown
// — ATX headings, **bold**, `inline code`, fenced ``` code ```, and lists — so
// rendering it as plain text left `##`/`**`/``` ``` ``` visible. Supports the
// subset findings actually use. No external deps.
import * as React from "react";

function renderInline(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|https?:\/\/[^\s)]+)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      parts.push(
        <code
          key={key++}
          className="rounded bg-muted px-1 py-0.5 mono text-[11px] text-foreground break-all"
        >
          {tok.slice(1, -1)}
        </code>,
      );
    } else if (tok.startsWith("**")) {
      parts.push(
        <strong key={key++} className="font-semibold text-foreground">
          {tok.slice(2, -2)}
        </strong>,
      );
    } else {
      parts.push(
        <a
          key={key++}
          href={tok}
          target="_blank"
          rel="noreferrer"
          className="break-all underline underline-offset-2 hover:text-foreground"
        >
          {tok}
        </a>,
      );
    }
    last = m.index + tok.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

type Segment = { type: "code"; content: string } | { type: "text"; content: string };

function parseSegments(src: string): Segment[] {
  const normalized = src.replace(/\r\n/g, "\n").replace(/^\n+|\n+$/g, "");
  const segments: Segment[] = [];
  const lines = normalized.split("\n");
  const fenceOpen = /^( {0,3})(`{3,}|~{3,})([^\n]*)$/;
  let textBuf: string[] = [];
  const flush = () => {
    if (textBuf.length) {
      segments.push({ type: "text", content: textBuf.join("\n") });
      textBuf = [];
    }
  };
  for (let i = 0; i < lines.length; i++) {
    const open = lines[i].match(fenceOpen);
    if (!open) {
      textBuf.push(lines[i]);
      continue;
    }
    const fenceChar = open[2][0];
    flush();
    const codeLines: string[] = [];
    let j = i + 1;
    const closeRe = new RegExp(`^ {0,3}${fenceChar === "`" ? "`" : "~"}{3,}\\s*$`);
    for (; j < lines.length; j++) {
      if (closeRe.test(lines[j])) break;
      codeLines.push(lines[j]);
    }
    segments.push({ type: "code", content: codeLines.join("\n") });
    i = j;
  }
  flush();
  return segments;
}

function headingClass(level: number): string {
  return level <= 1
    ? "mt-1 text-sm font-semibold text-foreground"
    : level === 2
      ? "mt-1 text-[13px] font-semibold text-foreground"
      : "text-xs font-semibold uppercase tracking-wide text-muted-foreground";
}

function renderBlock(raw: string, key: string): React.ReactNode[] {
  const block = raw.replace(/\n+$/, "");
  if (!block.trim()) return [];
  const out: React.ReactNode[] = [];
  let buf: string[] = [];
  let n = 0;
  const flush = () => {
    const bl = buf.map((l) => l.trim()).filter(Boolean);
    buf = [];
    if (!bl.length) return;
    const isOrdered = bl.every((l) => /^\d+\.\s+/.test(l));
    const isBulleted = bl.every((l) => /^[-*]\s+/.test(l));
    if (isOrdered) {
      out.push(
        <ol key={`${key}-${n++}`} className="list-decimal space-y-1 pl-5">
          {bl.map((l, j) => (
            <li key={j}>{renderInline(l.replace(/^\d+\.\s+/, ""))}</li>
          ))}
        </ol>,
      );
    } else if (isBulleted) {
      out.push(
        <ul key={`${key}-${n++}`} className="list-disc space-y-1 pl-5">
          {bl.map((l, j) => (
            <li key={j}>{renderInline(l.replace(/^[-*]\s+/, ""))}</li>
          ))}
        </ul>,
      );
    } else {
      out.push(<p key={`${key}-${n++}`}>{renderInline(bl.join(" "))}</p>);
    }
  };
  for (const line of block.split("\n")) {
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      flush();
      out.push(
        <div key={`${key}-${n++}`} className={headingClass(h[1].length)}>
          {renderInline(h[2].replace(/\s*#+\s*$/, ""))}
        </div>,
      );
    } else {
      buf.push(line);
    }
  }
  flush();
  return out;
}

export function Markdown({ source }: { source?: string | null }) {
  if (!source || !source.trim()) return null;
  const segments = parseSegments(source);
  return (
    <div className="min-w-0 max-w-full space-y-2 text-sm leading-relaxed text-foreground/90 [overflow-wrap:anywhere]">
      {segments.flatMap((seg, i): React.ReactNode[] => {
        if (seg.type === "code") {
          return [
            <pre
              key={`c${i}`}
              className="max-h-72 min-w-0 max-w-full overflow-auto whitespace-pre-wrap rounded-md border border-border bg-black/40 p-3 mono text-[11px] leading-relaxed [overflow-wrap:anywhere]"
            >
              <code>{seg.content}</code>
            </pre>,
          ];
        }
        return seg.content.split(/\n{2,}/).flatMap((blk, j) => renderBlock(blk, `t${i}-${j}`));
      })}
    </div>
  );
}
