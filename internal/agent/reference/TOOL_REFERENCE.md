# Xalgorix canonical tool-call reference

This file is embedded into every agent system prompt. The registry schema is
the final authority, but these examples are the shortest safe forms to copy.

## XML syntax

Every tool call must be one complete block. Use one `parameter` tag per field:

```xml
<function=tool_name>
<parameter=field_name>value</parameter>
</function>
```

Rules:

- Use the exact tool and parameter names below; do not use JSON, `command=` prose, or nested parameter tags.
- Put every field in the same function block. Do not split one call across assistant messages.
- `terminal_execute` is the only tool that receives a shell command. `report_vulnerability` and `finish` do not have a `command` parameter.
- If a call is rejected for missing fields, make one complete corrected call. Do not resend the same malformed call.

## Core tools and parameters

### terminal_execute

Required: `command`.

```xml
<function=terminal_execute>
<parameter=command>curl -skI https://TARGET</parameter>
</function>
```

### http_request

Required: `url`. Optional: `method`, `headers` (JSON object), `body`,
`follow_redirects`, `timeout`, `max_bytes`.

```xml
<function=http_request>
<parameter=url>https://TARGET/api/path</parameter>
<parameter=method>GET</parameter>
<parameter=headers>{"Origin":"https://TARGET"}</parameter>
</function>
```

### browser_action

Required: `command`. Optional: `url`, `selector`, `text`, `code`, `direction`,
`tab_id`, `proxy`, `name`, `domain`, `timeout`, `fields`, `session_name`.

```xml
<function=browser_action>
<parameter=command>goto</parameter>
<parameter=url>https://TARGET/login</parameter>
</function>
```

### python_action

Required: `code`. Optional: `timeout` (seconds).

```xml
<function=python_action>
<parameter=code>print("test")</parameter>
</function>
```

### add_note / read_notes

`add_note` requires `key` and `value`. `read_notes` has optional `key` (omit it
to read all notes).

```xml
<function=add_note>
<parameter=key>Endpoint Inventory</parameter>
<parameter=value>/api/login
/api/users
/api/profile</parameter>
</function>
```

### report_vulnerability

Registry-required fields: `title`, `severity`, `description`.
`severity` is one of `critical`, `high`, `medium`, `low`, or `info`.

Policy-required for actionable severities (`critical` through `low`): include
actual `exploitation_proof` and a valid `verification_method` such as
`exploited`, `data_extracted`, `callback_received`, `error_based`,
`time_based`, `reflected`, or `authenticated`. `endpoint`, `target`, `method`,
CVSS fields, impact, technical analysis, PoC, remediation, and fix are
optional registry fields.

```xml
<function=report_vulnerability>
<parameter=title>Unauthenticated data exposure</parameter>
<parameter=severity>high</parameter>
<parameter=description>The endpoint returns customer records without authentication.</parameter>
<parameter=endpoint>https://TARGET/api/users</parameter>
<parameter=exploitation_proof>HTTP 200 returned 20 real records including email addresses.</parameter>
<parameter=verification_method>data_extracted</parameter>
</function>
```

If the reporting gate returns `REJECTED`, do not resubmit the same claim with
the same evidence. Correct the evidence once if it is genuinely exploitable;
otherwise record the observation with `add_note` and call `finish`.

### finish

Required: `summary`.

```xml
<function=finish>
<parameter=summary>Assessment complete. Findings already reported: ...</parameter>
</function>
```

After a report is rejected as a false positive or informational-only issue,
`finish` is the correct next action. Do not loop on report/finish calls.
