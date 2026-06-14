# F-001 — Requirements: 中文 PDF 报告

> 已拍板的 4 个决策：
> 1. 默认语言：**中文（`zh`）**
> 2. 严重度等级：**翻译成中文**（"严重/高/中/低"）
> 3. Discord 通知：**保持英文**（运维通道）
> 4. 字体来源：**混合（默认内置 + 用户可覆盖）**

## 1. 目标（一句话）

让中文用户开箱即用，**默认就能拿到一份全中文的 PDF 渗透测试报告**交付给甲方，无需任何额外配置。

## 2. 用户故事（context）

- **角色**：中文渗透测试工程师
- **触发**：一次扫描完成，agent 发 `Event{Type:"finished"}` 之后
- **动作**：**零配置**——装上就是中文版
- **期望**：打开 `report.pdf` 看，从封面到免责声明**每一页都是中文**；技术名词（SQLi/XSS/CVE）保留英文便于和漏洞库对照

## 3. 输入

**触发条件**：
- 扫描完成时（`executeScanSession` 走到 `generateReportAt` 那一段）

**配置输入**：
- 环境变量 `XALGORIX_REPORT_LANGUAGE`，取值 `"en"` 或 `"zh"`
- **默认 `"zh"`**（本次新装用户开箱即用中文）
- 老用户想保留英文：在 `~/.xalgorix.env` 加 `XALGORIX_REPORT_LANGUAGE=en`

**数据输入**（不动）：
- 现有 `reporting.Scan` 结构
- 现有 `reporting.Vuln` / `reporting.Event` 列表

## 4. 输出

**视觉**：
- 文件路径仍是 `<ScanDir>/report.pdf`（**不**改名）
- 封面标题、执行摘要、方法论章节、发现描述、复现步骤、影响分析、修复建议、免责声明**全部中文**
- 22 个测试阶段（如 "Reconnaissance"）的中文译名（参考固定对照表）
- 漏洞严重度等级**翻译**：
  - Critical → **严重**
  - High → **高**
  - Medium → **中**
  - Low → **低**
- 漏洞类型名（SQLi/XSS/SSTI/SSRF/IDOR/...）**保留英文**

**数据**：
- 写入磁盘：`report.pdf`（同路径替换）
- WebSocket 广播：现有 `report_ready` 事件不变（只是 PDF 内容换了）

**副作用**：
- Discord 通知文案**保持英文**（运维通道，与语言解耦）

## 5. 边界情况

- **env 变量未设置** → 默认出**中文**报告
- **env 变量取其他值**（如 `"jp"`、`"fr"`） → **不识别**，fallback **中文**，并在启动时打 warning log
- **字体加载失败** → 报告生成失败，UI 显示明确错误信息（"中文字体加载失败，无法生成 PDF"），**不**退化成英文
- **首次构建时** → 字体文件随项目二进制一起发布（通过 `//go:embed` 嵌入），不引入运行时下载
- **22 阶段译名一致性** → 用一张固定的中英对照表（放在 `internal/reporting/i18n/zh.go`），所有阶段用同一张表，**不**让 LLM 临时翻译
- **重跑扫描**（`sess.resetState=true`）→ 仍然按当前 env 变量决定语言
- **用户提供的字体不可读**（路径错误 / 格式不对） → 启动时报错并退出（不悄悄回退内置字体，避免静默偏差）

## 6. 中文字体（关键技术约束）

**默认字体**：
- **Noto Sans CJK SC Regular**（Google 开源，Apache 2.0 协议）
- 选它的理由：**最通用、全球部署最广、Apache 2.0 协议可自由打包**、覆盖简体/繁体/日文/韩文
- 文件格式：OTF（TrueType 轮廓，对 fpdf 兼容性最好）
- 预估大小：~10MB（Regular 字重），嵌入二进制后总体积增加可接受

**下载与发布**：
- 构建时（`make build`）自动从 Google Fonts 官方仓库下载到 `internal/reporting/fonts/NotoSansCJKsc-Regular.otf`
- 字体文件**不进 git**（加入 `.gitignore`），构建时按需下载
- 通过 `//go:embed fonts/*.otf` 嵌入二进制
- 提供**离线构建**选项：`make build-offline`（如果 `internal/reporting/fonts/` 已有字体则跳过下载）

**用户覆盖**（可选）：
- 环境变量 `XALGORIX_REPORT_FONT_PATH` 指向用户自己的 `.ttf` / `.otf` 文件
- 用途：用户想用公司品牌字体 / 想用更小的子集字体
- 优先级：**用户 env 路径 > 内置默认字体**
- **不**支持运行时下载任意 URL（避免供应链风险）

**字体加载失败的回退**：
- **不**回退到英文。报错并明确告诉用户："中文字体加载失败，PDF 无法生成"
- 启动时检查（`config.Get()` 之后、第一次 `Generate` 之前）—— 提前 fail fast

## 7. 验收标准（必须可测）

- [ ] 在干净 tree 上 `./init.sh` 退出码 0
- [ ] **首次构建自动下载**字体：`make build` 把 `NotoSansCJKsc-Regular.otf` 放进 `internal/reporting/fonts/`
- [ ] `go build` 后的二进制大小增加 < 15MB（验证字体被嵌入）
- [ ] **不**设 env 变量跑一次扫描，PDF **是中文**（默认行为）
- [ ] 设 `XALGORIX_REPORT_LANGUAGE=en` 跑一次，PDF 是英文（**老用户回归**）
- [ ] 打开 PDF 翻 5 页，**每页都有中文字符正确显示**（不是方框/乱码）
- [ ] 22 阶段方法论章节显示中文译名
- [ ] 至少 1 个 finding 的描述/复现/修复是中文
- [ ] 严重度等级显示为"严重/高/中/低"（不是 Critical/High/Medium/Low）
- [ ] 免责声明是中文
- [ ] 设 `XALGORIX_REPORT_LANGUAGE=jp` 跑一次，PDF 仍是中文 + 启动时有 warning log
- [ ] 设 `XALGORIX_REPORT_FONT_PATH=/nonexistent.ttf` 启动，启动失败并明确报错
- [ ] `go test -race ./internal/reporting/...` 通过
- [ ] 新增至少 1 个单测覆盖"中文 vs 英文分支选择"

---

## 完成度自检

- [x] 6 个问题都有具体答案
- [x] 至少 3 个"边界情况"被识别
- [x] 字体来源、加载失败回退都已写明
- [x] 验收标准里至少 2 项是"打开 PDF 手动看"
- [x] 至少 1 项是回归测试
- [x] 至少 1 项是自动化测试
- [x] 至少 1 项是"用户覆盖字体"路径
