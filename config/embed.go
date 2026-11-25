package config

import _ "embed"

// SchemaJSON embeds the canonical V2/V3/V4 profile JSON Schema (Draft 2020-12).
//
//go:embed schema.json
var SchemaJSON []byte
