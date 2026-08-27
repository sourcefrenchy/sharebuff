// Package web embeds the static retrieve page for the self-hosted server.
// The same files are served as-is by the Cloudflare Worker (assets binding).
package web

import "embed"

//go:embed index.html style.css app.js crypto.js wordlist.js scrypt.js logo.svg integrity.json
var FS embed.FS
