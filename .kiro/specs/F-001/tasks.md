# F-001 — Tasks: 中文 PDF 报告

> 施工清单。每项 5–30 分钟，每项完成后跑 `./init.sh --no-webui`，每项独立 commit。
> **不跳任务**。卡住就更新 `session-handoff.md`。

---

## Task 1 — 准备

- [ ] 切到新分支：`git checkout -b feature/F-001-zh-pdf`
- [ ] 干净 tree 上跑 `./init.sh --no-webui`，确认 baseline 绿
- [ ] 把 `feature_list.json` 里的 F-001 `evidence.branch` 改成 `feature/F-001-zh-pdf`
- [ ] commit: (无，只是 baseline 确认)

> 验证：`./init.sh --no-webui` 退出码 0；`git status` 干净。

---

## Task 2 — Config 加两个字段

- [ ] `internal/config/config.go` 的 `Config` struct 加：
  - `ReportLanguage string  // XALGORIX_REPORT_LANGUAGE, 默认 "zh"`
  - `ReportFontPath string  // XALGORIX_REPORT_FONT_PATH, 默认 ""`
- [ ] `load()` 函数里加 `envOr("XALGORIX_REPORT_LANGUAGE", "zh")` 和 `envOr("XALGORIX_REPORT_FONT_PATH", "")`
- [ ] `Validate()` 加检查：`ReportLanguage` 必须是空、`"en"`、`"zh"` 之一
- [ ] commit: `wip: F-001 — add ReportLanguage and ReportFontPath config fields`
- [ ] 跑 `./init.sh --no-webui`

> 验证：build 通过；`config_test.go` 如有则补 1 个 case。

---

## Task 3 — i18n 子包骨架 + 英文 bundle（重构路径）

- [ ] 新建 `internal/reporting/i18n/i18n.go`：定义 `Lang` enum、`Bundle` 结构、`ParseLang(s) Lang`、`Get(lang Lang) *Bundle`、内部 `newBundleEn()`
- [ ] 新建 `internal/reporting/i18n/en.go`：把现在散落在 `generate.go` 里的所有英文字符串（章节标题、严重度标签、字段标签、免责声明）汇总成 `newBundleEn()`
- [ ] 现有 `MethodologyPhaseNames` map **不动**，但 i18n 的 Bundle 里同时包含它的快照
- [ ] 加测试 `internal/reporting/i18n/i18n_test.go`：
  - `TestParseLang`（`""` → zh, `"zh"` → zh, `"en"` → en, `"jp"` → zh + caller decides warning）
  - `TestBundleEn_NonEmpty`（每个字段都非空）
- [ ] commit: `wip: F-001 — add i18n package skeleton with English bundle`
- [ ] 跑 `./init.sh --no-webui` + `go test -race ./internal/reporting/i18n/...`

> 验证：新包能 import；测试全过；`generate.go` **还**未动（行为不变）。

---

## Task 4 — 中文 bundle（含 22 阶段译名）

- [ ] 新建 `internal/reporting/i18n/zh.go`：实现 `newBundleZh()`
- [ ] 加测试 `TestBundleZh_NonEmpty`、`TestBundleZh_22Phases`（断言 22 个阶段名都非空且唯一）
- [ ] **22 阶段中文译名**（参考初版，你可以改）：

| # | 英文 | 中文初版 |
|---|------|----------|
| 1 | Deep Reconnaissance & Attack Surface Mapping | 深度侦察与攻击面测绘 |
| 2 | Manual Vulnerability Discovery | 手动漏洞发现 |
| 3 | Directory & File Discovery | 目录与文件发现 |
| 4 | CORS & Cookie Analysis | CORS 与 Cookie 分析 |
| 5 | Authentication & Session Testing | 身份认证与会话测试 |
| 6 | Injection Testing | 注入测试 |
| 7 | SSRF Testing | SSRF 测试 |
| 8 | IDOR & Broken Access Control | IDOR 与越权访问控制 |
| 9 | API & GraphQL Testing | API 与 GraphQL 测试 |
| 10 | File Upload Testing | 文件上传测试 |
| 11 | Deserialization & RCE | 反序列化与远程代码执行 |
| 12 | Race Conditions & Business Logic | 竞态条件与业务逻辑 |
| 13 | Subdomain Takeover | 子域接管 |
| 14 | Open Redirect Testing | 开放重定向测试 |
| 15 | Email Security Testing | 邮件安全测试 |
| 16 | Cloud & Infrastructure | 云与基础设施 |
| 17 | WebSocket Testing | WebSocket 测试 |
| 18 | CMS-Specific Testing | 特定 CMS 测试 |
| 19 | Broken Link Hijacking & Content Spoofing | 失效链接劫持与内容欺骗 |
| 20 | Exploit Verification | 漏洞验证 |
| 21 | Zero-Day & Novel Vulnerability Discovery | 零日与新型漏洞发现 |
| 22 | Final Report | 最终报告 |

- [ ] commit: `wip: F-001 — add Chinese translation bundle with 22 phase names`
- [ ] 跑 `./init.sh --no-webui`

> 验证：测试过；你可以 review 译名，**觉得不妥直接改 i18n/zh.go**。

---

## Task 5 — Phase.Name + SeverityLabel 助手

- [ ] `internal/reporting/methodology.go` 加 `Phase` 类型（如果还没有）+ `func (p Phase) Name(b *i18n.Bundle) string` 方法
- [ ] `internal/reporting/severity.go` 加 `func SeverityLabel(sev string, b *i18n.Bundle) string`
  - `"critical"` → `b.SevCritical`（zh: "严重"）
  - `"high"` → `b.SevHigh`（zh: "高"）
  - `"medium"` → `b.SevMedium`（zh: "中"）
  - `"low"` → `b.SevLow`（zh: "低"）
  - 其它 → `b.SevInfo`（zh: "信息"）
- [ ] 加测试 `TestPhaseName`、`TestSeverityLabel_BothLanguages`
- [ ] commit: `wip: F-001 — add localized Phase.Name and SeverityLabel helpers`
- [ ] 跑 `./init.sh --no-webui`

> 验证：测试过；generate.go 仍未动。

---

## Task 6 — 字体下载与嵌入基础设施

- [ ] 新建 `scripts/download-font.sh`：从 Google Fonts 仓库下载 `NotoSansCJKsc-Regular.otf` 到 `internal/reporting/fonts/`
  - 加 size sanity check（> 5MB 算成功）
  - 加 OTF magic bytes check（前 4 字节 = `OTTO`）
  - 幂等：文件已存在则跳过
- [ ] 新建 `internal/reporting/fonts/fonts.go`：
  ```go
  //go:embed NotoSansCJKsc-Regular.otf
  var embeddedOTF []byte
  func Load(userPath string) ([]byte, error)
  ```
  - 优先读 userPath；空则用 embeddedOTF
  - 失败返回显式 error（不静默回退）
- [ ] `Makefile` 加 `download-font` target；`build` target 依赖它
- [ ] `.gitignore` 加 `internal/reporting/fonts/*.otf`
- [ ] 跑 `make download-font`，确认字体落位
- [ ] commit: `wip: F-001 — add CJK font download, embed, and Makefile target`
- [ ] 跑 `./init.sh --no-webui`

> 验证：`ls -lh internal/reporting/fonts/` 显示 .otf 文件 > 5MB；go build 仍过。

---

## Task 7 — generate.go 接入 Bundle + 字体（不破现有行为）

- [ ] `internal/reporting/generate.go` 的 `Options` struct 加 `ReportLanguage string` 和 `FontPath string`
- [ ] `Generate()` 函数开头加：
  - `bundle := i18n.Get(i18n.ParseLang(opts.ReportLanguage))`
  - `fontBytes, err := fonts.Load(opts.FontPath)`；err 直接返回
  - `pdf.AddUTF8FontFromBytes("noto", "", fontBytes)`（或等效 API，需实测 fpdf）
- [ ] 把 generate.go 里的关键字符串（封面标题、章节标题、严重度标签、免责声明）替换为 `bundle.XXX`
- [ ] 注释：`// generate.go 还在过渡期，Task 8 把剩余字符串全替换`
- [ ] commit: `wip: F-001 — refactor generate.go to use i18n bundle and CJK font (partial)`
- [ ] 跑 `./init.sh --no-webui`

> **关键验证**：现有英文 PDF 必须**仍能正常生成**（这是回归测试）。可以拿一个历史 scan 目录跑一次 `generateReportAt`，肉眼对比。

---

## Task 8 — 扫干净 generate.go 里剩余硬编码字符串

- [ ] grep `generate.go` 找剩余的英文 literal
- [ ] 全部替换为 `bundle.XXX`
- [ ] commit: `wip: F-001 — wire all section titles and labels through i18n bundle`
- [ ] 跑 `./init.sh --no-webui`

> 验证：英文 PDF 与重构前**视觉一致**（颜色、布局可以微调，但章节顺序、字段含义不能变）。

---

## Task 9 — 端到端冒烟测试（出第一份中文 PDF）

- [ ] 干净 tree 跑 `make build`
- [ ] 设 `export XALGORIX_REPORT_LANGUAGE=zh`（或不设，走默认）
- [ ] 用一个**已有 scan 目录**做 fixture（不需要重跑扫描），手动调 `reporting.Generate` 或通过 web 跑一次小扫描
- [ ] 打开 PDF 翻 5 页，**每页都有中文字符正确显示**（不是方框/乱码）
- [ ] 验证 22 阶段显示中文、严重度显示"严重/高/中/低"
- [ ] commit: (无，纯验证)

> 验证：PDF 能打开、中文渲染正确。如果没有 fixture scan 数据，临时写个最小 `Scan{}` struct 喂给 `Generate()`。

---

## Task 10 — 自动化测试覆盖"语言分支"

- [ ] `internal/reporting/generate_test.go` 加：
  - `TestGenerate_English_NoPanic` —— opts.ReportLanguage = "en"，断言 err == nil 且文件 > 1KB
  - `TestGenerate_Chinese_NoPanic` —— opts.ReportLanguage = "zh"，断言 err == nil 且文件 > 1KB
  - `TestGenerate_PDFMagicBytes` —— 两种语言都断言前 4 字节 = `%PDF`
- [ ] `internal/reporting/i18n/i18n_test.go` 加：
  - `TestSeverityLabel_BothLanguages` —— zh 拿"严重"，en 拿"Critical"
- [ ] commit: `wip: F-001 — add language branch and CJK render tests`
- [ ] 跑 `./init.sh --no-webui` + `go test -race ./internal/reporting/...`

> 验证：所有新测试过；race detector 干净。

---

## Task 11 — 用户覆盖字体路径

- [ ] 手动测试：`XALGORIX_REPORT_FONT_PATH=/nonexistent.ttf` → 启动应报错并退出
- [ ] 手动测试：`XALGORIX_REPORT_FONT_PATH=path/to/real.ttf` → 报告应使用该字体
- [ ] 加测试 `TestFontsLoad_UserOverrideSuccess`、`TestFontsLoad_UserPathMissing`（期望 error）
- [ ] commit: `wip: F-001 — add font path override tests`
- [ ] 跑 `./init.sh --no-webui`

> 验证：错误路径不静默回退；成功路径确实用到了用户字体。

---

## Task 12 — 文档

- [ ] `README.md` 的"Environment Variables"表加 `XALGORIX_REPORT_LANGUAGE` 和 `XALGORIX_REPORT_FONT_PATH` 两条
- [ ] `CHANGELOG.md` 加新版本条目（`## [Unreleased]` 或下一个版本号下）
- [ ] commit: `docs: F-001 — document REPORT_LANGUAGE and REPORT_FONT_PATH`
- [ ] 跑 `./init.sh --no-webui`

> 验证：文档渲染正常；链接没破。

---

## Task 13 — 全量验收

- [ ] 跑**完整** `./init.sh`（含 webui 构建）
- [ ] 检查二进制大小：`ls -lh build/xalgorix`；与 baseline 对比，增加 < 15MB
- [ ] 对照 `feature_list.json` 里的 8 条 `acceptance_criteria`，**每条**实测一遍：
  1. 默认行为出中文 PDF ✓
  2. `XALGORIX_REPORT_LANGUAGE=en` 出英文 PDF（老用户回归）✓
  3. 22 阶段、严重度、finding、免责声明全中文 ✓
  4. 技术名词（SQLi/XSS/CVE）保留英文 ✓
  5. `make build` 自动下载字体 ✓
  6. `XALGORIX_REPORT_FONT_PATH` 覆盖内置字体 ✓
  7. `go test -race ./internal/reporting/...` 通过 ✓
  8. 至少 1 个测试覆盖"语言分支" ✓
- [ ] commit: (任何最终清理)

> 验证：8/8 都打勾。

---

## Task 14 — 收尾

- [ ] `feature_list.json`：F-001 `status: "done"`，`evidence.commits` 填 6-10 个 commit SHA
- [ ] `feature_list.json`：`active_feature_id: null`（或 `"F-002"` 如果你想紧接着做下一个）
- [ ] `progress.md`：在证据日志加 F-001 完成那一行
- [ ] 跑**最后一次** `./init.sh --no-webui`
- [ ] 覆盖 `session-handoff.md`：
  - 标 F-001 done
  - 列 F-001 实际用了几个 commit
  - 列 F-002 候选（如果你已经有了的话）
  - 写下一个 session 的 first 3 actions
- [ ] 合并分支到 main（或按你项目的 PR 流程开 PR）
- [ ] commit: (收尾的所有变更一起)

> 验证：clean working tree；handoff 文件就位；feature_list.json 状态正确。

---

## 完成度自检

- [x] 14 个 task，每个都有"验证产出"
- [x] Task 7 + Task 8 是**两阶段重构**（先 partial + 回归验证，再扫干净）
- [x] 至少 2 个 task 是"测试"（Task 10、11）
- [x] Task 9 是**手动冒烟**（不是自动化）
- [x] Task 13 是**全量验收**（对照 acceptance_criteria 一条条勾）
- [x] Task 14 是**收尾**（不是"再改改"）
