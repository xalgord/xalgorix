# F-001 — Design: 中文 PDF 报告

> 设计阶段：讲"代码怎么改"。不写代码，只画图、列文件、做决策。
> 写完后给 AI review，确认后再写 `tasks.md`。

## 1. 数据流

```
┌──────────────────────────────────────────────────────────────────┐
│ 启动                                                             │
│   main.go → config.Get() → cfg.ReportLanguage (默认 "zh")         │
│   main.go → config.Get() → cfg.ReportFontPath  (默认 "")          │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ 一次扫描完成                                                      │
│   server.go:executeScanSession                                    │
│     → sess.cfg.ReportLanguage → 透传给 reporting.Options         │
│     → 调 s.generateReportAt(sess.record, sess.scanDir)            │
│         → 调 reporting.Generate(scan, opts)                       │
│             → opts.ReportLanguage → 选 i18n.Bundle                │
│             → opts.FontPath 优先级 > 内置嵌入字体                  │
│             → 用 fpdf 注册 CJK 字体                                │
│             → 渲染各章节（i18n.Bundle.Xxx 取代内联英文字符串）       │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ 输出                                                             │
│   <ScanDir>/report.pdf （路径不变，仅内容换语言）                  │
│   现有 WebSocket "report_ready" 事件不变                            │
│   现有 Discord 通知文案保持英文                                    │
└──────────────────────────────────────────────────────────────────┘
```

## 2. 文件清单

### 新增（5 个）

| 文件 | 作用 |
|------|------|
| `internal/reporting/i18n/i18n.go` | Lang 枚举 + Bundle 结构 + `ParseLang(s) Lang` + `Get(Lang) *Bundle` |
| `internal/reporting/i18n/zh.go` | `newBundleZh()` —— 22 阶段中文译名 + 章节标题 + 严重度标签 + 免责声明 |
| `internal/reporting/i18n/en.go` | `newBundleEn()` —— 把现有散落在 generate.go 里的英文字符串集中到这 |
| `internal/reporting/fonts/fonts.go` | 字体加载：`//go:embed` 内置 OTF + 用户覆盖路径 + 校验 |
| `scripts/download-font.sh` | Make 调用的字体下载脚本（curl + checksum 校验） |

### 修改（6 个）

| 文件 | 改什么 | 为什么 |
|------|--------|-------|
| `internal/reporting/generate.go` | 接收 `opts.ReportLanguage`、`opts.FontPath`；按 Bundle 输出；注册 CJK 字体 | 主入口 |
| `internal/reporting/methodology.go` | 加 `func (p Phase) Name(b *i18n.Bundle) string` 方法 | 阶段名 i18n |
| `internal/reporting/severity.go` | 加 `func SeverityLabel(s Severity, b *i18n.Bundle) string` | 严重度翻译 |
| `internal/config/config.go` | `Config` 加 `ReportLanguage` 和 `ReportFontPath` 两字段 + envOr + Validate 检查 | 配配置 |
| `Makefile` | 加 `download-font` target；`build` target 依赖它 | 构建时下载字体 |
| `.gitignore` | 加 `internal/reporting/fonts/*.otf` | 字体不进 git |

### 关键约束

- `internal/reporting/methodology.go` 现有的 `MethodologyPhaseNames` map **不动**（它被 `internal/web` 的 phase-filter 引用），i18n 翻译通过 `Phase.Name(bundle)` 间接走
- `reporting.Scan` / `Vuln` / `Event` 类型**不动**
- 现有 `SeverityCounts` 结构**不动**（counts 永远是数字，labels 在显示层翻译）

## 3. 关键接口

```go
// internal/reporting/i18n/i18n.go
package i18n

type Lang string
const (
    LangEN Lang = "en"
    LangZH Lang = "zh"
)

// ParseLang 把环境变量字符串规范成 Lang。未知值返回 LangZH（默认），
// 由调用方负责打 warning。
func ParseLang(s string) Lang

// Bundle 是一份"所有需要本地化的字符串"的快照。
// 设计要点：零依赖、零反射、内存常驻（一次 Generate 一份）。
type Bundle struct {
    Lang Lang

    // 章节标题
    CoverSubtitle    string  // "自主 AI 渗透测试报告"
    ExecSummaryTitle string
    MethodologyTitle string
    ReconTitle       string
    FindingsTitle    string
    VulnDetailTitle  string
    DisclaimerTitle  string

    // 22 阶段名（索引 = 阶段号 1..22）
    PhaseNames [23]string

    // OWASP 分类
    OWASPCategories [10]struct{ ID, Name string }

    // 严重度标签
    SevCritical string  // zh: "严重"
    SevHigh     string  // zh: "高"
    SevMedium   string  // zh: "中"
    SevLow      string  // zh: "低"
    SevInfo     string  // zh: "信息"

    // 状态/字段标签
    StatusRunning   string
    StatusFinished  string
    StatusStopped   string
    TargetLabel     string  // "目标"
    StartedLabel    string  // "开始时间"
    FinishedLabel   string  // "结束时间"
    DurationLabel   string  // "耗时"
    SeverityLabel   string  // "严重度"

    // 免责声明全文
    Disclaimer string
}

// Get 返回一份对应语言的 Bundle。Bundle 是只读副本，并发安全。
func Get(lang Lang) *Bundle
```

```go
// internal/reporting/methodology.go（新增方法）
type Phase int
func (p Phase) Name(b *i18n.Bundle) string {
    if p < 1 || p > 22 { return "" }
    return b.PhaseNames[p]
}
```

```go
// internal/reporting/severity.go（新增函数）
func SeverityLabel(sev Severity, b *i18n.Bundle) string {
    switch sev {
    case SevCritical: return b.SevCritical
    case SevHigh:     return b.SevHigh
    case SevMedium:   return b.SevMedium
    case SevLow:      return b.SevLow
    }
    return b.SevInfo
}
```

```go
// internal/reporting/fonts/fonts.go
package fonts

// Load 解析字体：优先用户路径，空则用内置嵌入的。
// 错误时返回显式 error（不静默回退）。
func Load(userPath string) ([]byte, error)

//go:embed NotoSansCJKsc-Regular.otf
var embeddedOTF []byte  // 构建时由 download-font 脚本放进 fonts/ 目录
```

```go
// internal/reporting/generate.go（Options 结构扩展）
type Options struct {
    LogoPath       string
    ScanDir        string
    FallbackDir    string
    ReportLanguage string  // 新增："en" | "zh"，默认 "zh"
    FontPath       string  // 新增：用户覆盖路径，默认 ""
}
```

```go
// internal/config/config.go（Config 结构扩展）
type Config struct {
    // ... 现有字段 ...
    ReportLanguage string  // XALGORIX_REPORT_LANGUAGE，默认 "zh"
    ReportFontPath string  // XALGORIX_REPORT_FONT_PATH，默认 ""
}

func (c *Config) Validate() error {
    // 现有检查 ...
    if lang := c.ReportLanguage; lang != "" && lang != "en" && lang != "zh" {
        return fmt.Errorf("XALGORIX_REPORT_LANGUAGE=%q not supported; use 'en' or 'zh'", lang)
    }
    return nil
}
```

## 4. 备选方案

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| A. i18n 子包 + Bundle（本次选） | 字符串集中；可扩展多语言；并发安全；零反射 | 多一个子包要维护 | ✅ |
| B. 两个独立函数 `GenerateEnglish` / `GenerateChinese` | 改动"少" | 几乎所有逻辑复制两份；后续维护灾难 | ❌ |
| C. 单个 map[string]string 全局 i18n | 简单粗暴 | 缺类型安全；拼写错误不报错 | ❌ |
| D. 用 github.com/nicksnyder/go-i18n 等成熟库 | 标准做法 | 多一个依赖；项目当前没有 i18n 依赖；为 2 种语言上重型库是过度工程 | ❌ |

| 字体方案 | 优点 | 缺点 | 结论 |
|---------|------|------|------|
| A. `//go:embed` 内置（本次选） | 离线可用；首启零延迟；一份二进制 | +10MB 二进制 | ✅ |
| B. 运行时从 URL 下载 | 二进制小 | 离线失败；供应链风险；首启延迟 | ❌ |
| C. 用户必须自备 | 最小二进制 | 新用户体验极差 | ❌ |
| D. 系统已装字体（fc-match） | 零嵌入 | 跨平台不一致；Docker/CI 容易缺字体 | ❌ |

## 5. 风险与缓解

| 风险 | 触发条件 | 缓解 |
|------|---------|------|
| 二进制增大 ~10MB | 始终（`//go:embed`） | 文档说明；gzip 后实际增加 ~5-7MB；与项目现状（~30-50MB）可接受 |
| 首次构建需要联网 | CI/Docker 全新环境无 `internal/reporting/fonts/NotoSansCJKsc-Regular.otf` | 提供 `make build-offline` 跳过下载；CI 缓存 `fonts/` 目录 |
| fpdf CJK 渲染异常 | fpdf 对 CJK 字体度量支持有 quirks | 走 happy path 实测；如果发现坑，可能要切到 fpdf 的 `AddUTF8FontFromBytes` API |
| 22 阶段中文译名分歧 | 业界对 "Reconnaissance" 等术语有多种译法 | 在 `i18n/zh.go` 顶部用注释明确"已选定的译名"；不暴露配置项；用户改 i18n/zh.go 即可换 |
| Discord 通知保持英文 | 用户已确认 | 不动 `sendDiscordWithFile` 调用的字符串字面量 |
| Phase 21 "Zero-Day" 翻译尴尬 | "零日" 在中文安全圈可用，但其他译法也有 | 在 `i18n/zh.go` 注释里说明"暂用'零日漏洞'，如有更好译法可改" |
| `//go:embed` 在缺字体文件时 build 失败 | 开发者本地未跑 `make download-font` | Makefile 的 `build` target 加 `download-font` 依赖；README 加一句"首次构建需要联网" |
| 测试覆盖不足 | 没有真扫一次产生报告 | 加一个 `TestGenerate_Chinese` fixture 跑一个最小 Scan 出 PDF，断言 (a) 不 panic (b) 文件 > 1KB (c) PDF magic bytes |

## 6. 涉及安全闸？

**不涉及。** 改动范围：
- `internal/reporting/` —— 输出层，不影响 agent 决策
- `internal/config/` —— 加两个新字段，不动现有 env 解析流程
- `Makefile` / `.gitignore` —— 构建与版本控制
- **不**触碰 `internal/safe` / `internal/scopeguard` / `internal/sandbox` / LLM 提示词

`feature_list.json` 里的 `touches_safety_critical` 保持 `false`。

## 7. 与现有约定的契合度

| 项目约定 | 本次如何遵守 |
|---------|------------|
| Go: `gofmt` 干净，`golangci-lint` 干净 | 新增代码遵守；用 `make lint` 验证 |
| Webui 改动后必须 `make webui` | 本次**不**改 webui |
| 永远不在 main 上直接改 | 在 `feature/F-001-zh-pdf` 分支开发 |
| Spec 先行 | ✅ 现在在做 |
| 复用现有 `MethodologyPhaseNames` map | i18n 翻译通过 `Phase.Name(bundle)` 间接走，不重写 map |
| 复用现有 `SeverityCounts` 统计 | counts 永远是数字，labels 在显示层翻译 |

---

## 完成度自检

- [x] 6 道 requirements 题都能从 design 里找到对应实现位置
- [x] 每个改动都有"为什么"
- [x] 考虑了 4 个备选方案并写明拒绝理由
- [x] 风险表里 6+ 条具体风险
- [x] 明确说"不涉及安全闸"
- [x] 改动文件清单 < 10 个
