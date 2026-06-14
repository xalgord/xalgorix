export const meta = {
  name: 'xalgorix-architecture-walkthrough',
  description: 'Architect deep-walkthrough of ~/code/xalgorix: core modules + daily runtime flow',
  phases: [
    { title: 'Map repo' },
    { title: 'Read core modules' },
    { title: 'Trace runtime flow' },
    { title: 'Synthesize walkthrough' },
  ],
}
const ROOT = '/home/ubuntu/code/xalgorix'
const SCHEMA = {
  type: 'object',
  properties: {
    sections: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          points: { type: 'array', items: { type: 'string' } },
        },
        required: ['title', 'points'],
      },
    },
  },
  required: ['sections'],
}

phase('Map repo')
const mapResult = await agent(
  `You are a 10-year architect. Scout the repo at ${ROOT} and produce a precise structural map.
- Read README.md, docs/ARCHITECTURE.md, go.mod, Makefile, cmd/xalgorix/*.go (entrypoints), and list every package under internal/.
- For each package under internal/, list the 5-10 most important .go files (give relative paths) and a one-line role description.
- Identify the binary entrypoint(s) and the build targets.
- Identify config loading mechanism (env file? flags? both?) and where ~/.xalgorix.env is parsed.
- Return concise findings as a bulleted map. No marketing prose.`,
  { phase: 'Map repo', schema: SCHEMA, label: 'repo map' }
)

phase('Read core modules')
const moduleResult = await agent(
  `You are a 10-year Go architect. Read the source at ${ROOT} and produce a deep walkthrough of the CORE MODULES.
Focus on these packages and explain, in code-grounded terms (file:line references), what each one does and how they collaborate:
- internal/agent (the autonomous agent loop)
- internal/llm (LLM client abstraction)
- internal/providers (concrete LLM providers)
- internal/tools (tool registry the agent invokes)
- internal/scanctx (scan context / state passed through the loop)
- internal/scopeguard (target/scope authorization checks)
- internal/safe (safety policies, sandboxing)
- internal/sandbox (command/process execution environment)
- internal/proxy (proxy support)
- internal/ratelimit
- internal/storage
- internal/reporting (PDF reports)
- internal/web (the --web dashboard: routes, websocket, server)
- internal/tui (the terminal UI built on bubbletea)
- internal/resources, internal/auth, internal/config
Also explain the public CLI surface in cmd/xalgorix.
For each module: purpose, key types/functions, IO boundaries, and the contract it exposes to its neighbors.
Return as ordered sections with bullet points and file:line citations.`,
  { phase: 'Read core modules', schema: SCHEMA, label: 'core modules' }
)

phase('Trace runtime flow')
const flowResult = await agent(
  `You are a 10-year architect. Trace the DAILY RUNTIME FLOW of xalgorix at ${ROOT} step-by-step.
Cover BOTH major entrypoints and how data flows between them:
1) CLI flow: user runs \`xalgorix <flags>\` — from flag parsing → config load → LLM provider init → agent loop startup → tool execution → result aggregation → reporting. Cite the actual functions called in order (file:line).
2) Web UI flow: user runs \`xalgorix --web\` — server bootstrap, HTTP routes, websocket upgrade, live agent telemetry pushed to browser, how a scan is started from the web UI and how its results stream back. Cite files.
3) Tool execution flow end-to-end for a representative tool (e.g. one that runs a CLI command or makes an HTTP request): scope guard check → rate-limit check → sandbox exec → result normalization → reporting/storage.
4) LLM call flow: how a prompt is built, sent to the provider, response parsed, tool calls dispatched, streaming vs non-streaming, and how the agent decides to continue or stop.
5) Persistence: where scans/results are stored on disk, schema, and how the web UI reads them.
6) Safety rails: which checks happen BEFORE any external action (network/HTTP, command exec) and which happen AFTER.
Return a chronological numbered trace with file:line citations for each step.`,
  { phase: 'Trace runtime flow', schema: SCHEMA, label: 'runtime flow' }
)

phase('Synthesize walkthrough')
const synth = await agent(
  `You are a 10-year architect writing a guided walkthrough for a new engineer who will read the xalgorix codebase at ${ROOT} tomorrow.
You have three prior reports:
1) Repo map:
${JSON.stringify(mapResult)}
2) Core modules:
${JSON.stringify(moduleResult)}
3) Runtime flow:
${JSON.stringify(flowResult)}

Write ONE cohesive, well-structured walkthrough in Markdown with these sections (in Chinese, 资深架构师口吻,简洁有力):
- 一句话项目定位
- 顶层架构(分层图,用 ASCII 或 mermaid 均可)
- 核心模块逐个解读(按重要性排序,每模块包含:职责/关键文件/上下游契约/设计亮点或坑)
- 日常运行流程(CLI 与 Web UI 两条主线,按时间线逐步,引用 file:line)
- 数据/状态生命周期(配置 → 扫描 → 报告 → 持久化)
- 安全边界(scope guard / safe / sandbox / ratelimit 的检查顺序)
- 给新人的阅读顺序建议(先读哪 5 个文件,再读哪 10 个,最后读哪些)
Keep it dense, no fluff, no marketing. Use code paths with file:line.`,
  { phase: 'Synthesize walkthrough', label: 'synthesis' }
)

return synth
