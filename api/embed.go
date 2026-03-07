package main

import "embed"

// WebDist holds the compiled React web application. It is populated by
// `make build-ui` which copies web/dist → api/web_dist before compilation.
// The all: prefix ensures hidden files (e.g. .gitkeep) are also embedded.
//
//go:embed all:web_dist
var WebDist embed.FS
