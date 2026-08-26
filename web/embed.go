// Package web embeds the static retrieve page for the self-hosted server.
// The same files are served as-is by the Cloudflare Worker (assets binding).
package web

import "embed"

//go:embed index.html style.css app.js crypto.js scrypt.js logo.svg
var FS embed.FS
