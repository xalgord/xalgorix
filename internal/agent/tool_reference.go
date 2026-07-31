package agent

import _ "embed"

// embeddedToolReference is kept as a file rather than an inline string so
// parameter corrections have one reviewable reference that can be updated
// alongside the registry and prompt examples.
//
//go:embed reference/TOOL_REFERENCE.md
var embeddedToolReference string
