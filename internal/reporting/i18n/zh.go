package i18n

// newBundleZh returns the Simplified Chinese string bundle (F-001 default).
//
// Translation conventions:
//
//   - Technical terms (SQLi, XSS, CVE, CWE, OWASP, CVSS, IDOR, SSRF, etc.)
//     are kept in English because the Chinese security community uses
//     them as-is. This matches the spec locked at F-001 review.
//
//   - Severity labels ARE translated per user decision: 严重 / 高 / 中 / 低 / 信息.
//
//   - Phase names are translated as a single fixed set; a comment in
//     tasks.md explains the chosen translations. Update here if you
//     change them; do not surface as a config option.
func newBundleZh() *Bundle {
	return &Bundle{
		Lang: LangZH,

		// Cover & brand
		CoverBrand:           "Xalgorix",
		CoverSubtitle:        "自主 AI 驱动的安全评估",
		CoverScanIDLabel:     "扫描 ID",
		CoverReportName:      "安全评估报告",
		LabelTotalVulns:      "漏洞总数",
		LabelToolCalls:       "工具调用次数",
		LabelTotalTokens:     "Token 总数",
		LabelScanStart:       "扫描开始",
		LabelScanEnd:         "扫描结束",
		LabelReconIPs:        "已解析的 IP 地址",
		LabelReconPorts:      "开放端口与服务",
		LabelReconTechs:      "已识别的技术栈",
		LabelReconURLs:       "观察到的 URL 与端点",
		CategoryIntelGather:  "情报收集",
		CategoryVulnAnalysis: "漏洞分析",
		LabelNotRecorded:     "未记录",

		// Section titles
		SectionExecSummary: "执行摘要",
		SectionRiskAssess:  "风险评估",
		SectionScanDetails: "扫描详情",
		SectionMethodology: "测试方法论",
		SectionRecon:       "侦察结果",
		SectionBlueTeam:    "蓝队参考时间戳",
		SectionFindings:    "发现概览",
		SectionVulnDetail:  "漏洞详情",
		SectionEndpoints:   "已测试的端点与 URL",
		SectionRefIndex:    "参考索引",
		SectionCWERef:      "CWE 参考表",
		SectionOWASPRef:    "OWASP Top 10 (2021) 覆盖情况",
		SectionPTESMap:     "PTES 阶段映射",
		SectionDisclaimer:  "免责声明",

		// Severity labels — TRANSLATED per F-001 user decision
		SevCritical: "严重",
		SevHigh:     "高",
		SevMedium:   "中",
		SevLow:      "低",
		SevInfo:     "信息",

		// Table column headers (kept in English where they are CWE/CVE-style labels)
		LabelID:       "ID",
		LabelFinding:  "发现",
		LabelSeverity: "严重度",
		LabelCVSS:     "CVSS",
		LabelCVE:      "CVE",
		LabelCWE:      "CWE",
		LabelOWASP:    "OWASP",
		LabelName:     "CWE 名称",
		LabelTitle:    "发现标题",
		LabelPhase:    "PTES 阶段",
		LabelFindings: "发现数",
		LabelStatus:   "状态",
		LabelCategory: "OWASP 分类",

		// Status indicators
		StatusFound:    "已发现",
		StatusClear:    "未发现",
		StatusTested:   "已测试",
		StatusExecuted: "已执行",
		StatusSkipped:  "已跳过",

		// Field labels
		LabelCVSSValue: "CVSS：",
		LabelCVEValue:  "CVE：",
		LabelMethod:    "方法：",
		LabelVerified:  "验证方式：%s",
		LabelRiskScore: "整体风险评分",

		// Phase row template (zh style)
		PhaseRowFmt: "第 %d 阶段：%s",

		// 22-phase methodology — chosen translations for F-001.
		// If you change these, also update .kiro/specs/F-001/tasks.md
		// so the design doc and the implementation stay in sync.
		PhaseNames: [23]string{
			0:  "",
			1:  "深度侦察与攻击面测绘",
			2:  "手动漏洞发现",
			3:  "目录与文件发现",
			4:  "CORS 与 Cookie 分析",
			5:  "身份认证与会话测试",
			6:  "注入测试",
			7:  "SSRF 测试",
			8:  "IDOR 与越权访问控制",
			9:  "API 与 GraphQL 测试",
			10: "文件上传测试",
			11: "反序列化与远程代码执行",
			12: "竞态条件与业务逻辑",
			13: "子域接管",
			14: "开放重定向测试",
			15: "邮件安全测试",
			16: "云与基础设施",
			17: "WebSocket 测试",
			18: "特定 CMS 测试",
			19: "失效链接劫持与内容欺骗",
			20: "漏洞验证",
			21: "零日与新型漏洞发现",
			22: "最终报告",
		},

		// OWASP Top 10 (2021) — categories translated, IDs kept.
		OWASPCategories: [10]struct{ ID, Name string }{
			{"A01", "访问控制失效"},
			{"A02", "加密机制失效"},
			{"A03", "注入"},
			{"A04", "不安全设计"},
			{"A05", "安全配置错误"},
			{"A06", "易受攻击和过时的组件"},
			{"A07", "身份识别和身份验证失败"},
			{"A08", "软件和数据完整性故障"},
			{"A09", "安全日志和监控故障"},
			{"A10", "服务端请求伪造 (SSRF)"},
		},

		// Disclaimer — translated to Chinese; structure mirrors English version.
		Disclaimer: `本次渗透测试由 Xalgorix —— 自主 AI 驱动的安全评估工具执行。报告中的发现基于自动化测试以及在可能情况下的手动验证。

重要提示：

* 范围：本次评估仅限于本报告明确列出的目标系统。范围之外的系统和服务未在测试范围内。

* 误报：尽管 Xalgorix 会在报告前尝试验证发现，但部分发现可能仍需人工验证。建议在采取修复措施前，验证所有严重和高危级别的发现。

* 局限性：自动化测试无法发现所有漏洞。建议结合手动测试、代码审查以及其他安全活动以实现全面的安全覆盖。

* 合法性：本次评估在获得目标所有者授权的前提下进行。未经授权的安全测试属于违法行为。在测试任何系统前，请确保已获得合法授权。

* 报告准确性：本报告按"原样"提供，不附带任何形式的担保。测试方法论与发现基于测试时可用的工具与技术。

* 修复建议：对于发现的任何漏洞，请遵循行业最佳实践进行修复。复杂的漏洞请咨询安全专业人士。

由 Xalgorix 生成 —— 自主 AI 渗透测试引擎
https://github.com/xalgord/xalgorix`,
	}
}
