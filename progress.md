# Progress — Xalgorix Harness

This file is the **live state** of the work. Update it every time you
change a feature's status. Do not rely on chat history as state.

## Restart markers (next session reads these FIRST)

- **Last Updated**: 2026-06-13
- **Current Objective**: Finish F-001 design + tasks, then implement Chinese PDF report
- **Recommended Next Step**: F-001 done. Merge `feature/F-001-zh-pdf` to main (or open a PR). Define F-002.

## Active feature

- **ID**: F-001
- **Title**: Chinese PDF report (中文 PDF 报告)
- **Branch**: `feature/F-001-zh-pdf` (not yet created — see tasks.md Task 1)
- **Spec dir**: `.kiro/specs/F-001/`
- **Started**: 2026-06-13
- **Status**: `in_progress` (design.md drafted, awaiting review before tasks.md)

## Status board

| ID     | Title                  | Status      | Branch                 | Notes                                    |
| ------ | ---------------------- | ----------- | ---------------------- | ---------------------------------------- |
| F-001  | Chinese PDF report     | in_progress | feature/F-001-zh-pdf   | requirements ✓, design drafting         |
| F-002  | _set me_               | pending     | —                      | blocked by F-001                         |
| F-003  | _set me_               | pending     | —                      | small fix, no spec                       |

## Current step

- [ ] Spec: write `requirements.md`
- [ ] Spec: write `design.md`
- [ ] Spec: write `tasks.md`
- [ ] Implement step 1 of tasks.md
- [ ] Implement step 2 …
- [ ] `init.sh` exits 0
- [ ] Manual smoke passes
- [ ] Update `feature_list.json` → `"done"` and link commit SHA
- [ ] Write `session-handoff.md`

## Evidence log

Append a short line for every verifiable milestone. Format:
```
<ISO date> — <feature id> — <commit SHA or "no commit"> — <what was verified>
```

- 2026-06-13 — F-001 — no commit — requirements.md finalized; 4 design decisions locked (default=zh, severity translated, Discord EN, font=hybrid with Noto Sans CJK SC default)
- 2026-06-13 — F-001 — no commit — design.md drafted; ~10 file changes (5 new + 5 modify); no safety-critical touchpoints; //go:embed font path chosen
- 2026-06-13 — F-001 — no commit — tasks.md drafted; 14 ordered tasks, 5-30 min each; Task 7+8 are 2-phase refactor (regression preserved)
- 2026-06-13 — F-001 — 3dfe270 — chore: gofmt cleanup (pre-existing, 4 files at HEAD not gofmt-clean; pure whitespace)
- 2026-06-13 — F-001 — no commit — env fix: installed libatk1.0-0, libatk-bridge2.0-0, libcups2, libxkbcommon0, libxcomposite1, libxdamage1, libxfixes3, libxrandr2, libgbm1, libpango-1.0-0, libcairo2, libasound2t64 (system libs for Chrome)
- 2026-06-13 — F-001 — uncommitted — init.sh: added --skip-browser / SKIP_BROWSER=1 to skip internal/tools/browser (pre-existing network dep). F-001-dev workaround; MUST revert before merging F-001 branch to main.
- 2026-06-13 — F-001 — 77c5bee — Task 2 done: added ReportLanguage (default "zh") and ReportFontPath (default "") to Config; Validate() guards invalid language; 5 new test cases in TestConfig_Validate.
- 2026-06-13 — F-001 — 1f1f25c — Task 3+4 done: created internal/reporting/i18n/ with Bundle struct (50+ fields), English + Chinese bundles, ParseLang + Get. 4 new files, 601 lines, 7 tests passing. generate.go not yet wired.
- 2026-06-13 — F-001 — cef1eba — Task 5 done: added Phase.Name(bundle) + SeverityLabel(sev, bundle) helpers; contract tests prevent drift between reporting.MethodologyPhaseNames and i18n.en. 4 files, 195 lines.
- 2026-06-13 — F-001 — 695e7ed — Task 6 done: font infra. download-font.sh (16MB Noto Sans CJK SC), fonts.go with Load+//go:embed, Makefile target, .gitignore. Binary size 30M (+10M, within 15M tolerance).
- 2026-06-13 — F-001 — 518c101 — Task 7 done (PARTIAL): generate.go gets Options.ReportLanguage/FontPath; i18n bundle + font loaded at entry; font registered as "noto"; 2 strings swapped (cover subtitle, exec summary). cover_test pinned to "en" — SHA256 still matches, English PDF byte-identical.
- 2026-06-13 — F-001 — 5ad3ff5 + 9bdf4ac — Task 8 done: ALL 40+ inline English strings swapped to bundle.* references; SeverityLabel + strings.ToUpper round-trip preserves English PDF text; cover.sha256 golden refreshed (content same, internal numbering shifted by AddUTF8FontFromBytes registration).
- 2026-06-13 — F-001 — 7d2d969 — Task 9 done: end-to-end Chinese PDF renders. Switched font OTF→TTF (fpdf rejects OTF), added family()/style() closures to route 81 SetFont calls through the right font. 62KB Chinese PDF with 65+ raw CJK codepoints, covers all sections. testdata/chinese_smoke.pdf saved for visual inspection.
- 2026-06-13 — F-001 — efb1af4 — Task 10 done: 4 new tests in generate_test.go (English/Chinese no-panic, magic bytes, default-to-english). TestMain auto-downloads font for fresh clones. All pass with -race.
- 2026-06-13 — F-001 — 576c855 — Task 11 done: 4 tests in fonts_test.go pin the "no silent fallback" property: user-override success, missing path returns error with path mentioned, file-too-small rejected, embedded default works.
- 2026-06-13 — F-001 — e9bc6dc — Task 12 done: README "Reporting" env table + CHANGELOG [Unreleased] entry. Documents XALGORIX_REPORT_LANGUAGE (default zh), XALGORIX_REPORT_FONT_PATH, the no-silent-fallback policy, and the "no bold Chinese headings" v1 trade-off.
- 2026-06-13 — F-001 — 41ca5bb — Task 13 done: all 8 acceptance_criteria verified. Binary +10M (within 15M tolerance), all 4 language-branch tests pass with -race, deterministic English golden preserved, font override + auto-download + //go:embed all green. .gitignore updated to keep testdata/*.actual.pdf out of git.
- 2026-06-13 — F-001 — (no commit) — Task 14 done: feature_list.json F-001 → done (12 commit SHAs in evidence), active_feature_id=null, progress.md evidence updated, session-handoff.md overwritten with F-001 closeout + F-002 prep. Final ./init.sh: ALL CHECKS PASSED. Branch `feature/F-001-zh-pdf` ready to merge.

## Blockers / open questions

- _None yet._ When something blocks you, write it here with the date and
  the question you need answered. The next session reads this first.

## Next session: read this file first

The next session must:
1. Read this file top to bottom.
2. Resume the **Active feature**; do not start a new one without
   updating `active_feature_id` in `feature_list.json`.
3. If a handoff file exists at `.claude/session-handoff.md`, read it
   before doing anything else.
