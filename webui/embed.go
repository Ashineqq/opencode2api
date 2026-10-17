// Package webui embeds the static management interface.
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"strings"
	"sync"
)

// Assets contains the static management interface served by the admin listener.
//
//go:embed index.html app.js styles.css
var Assets embed.FS

// AssetPaths are the files referenced from index.html whose content changes
// with the build.
var assetPaths = []string{"app.js", "styles.css"}

var (
	stampedOnce  sync.Once
	stampedIndex []byte
)

// IndexHTML returns index.html with its script and stylesheet references
// carrying a content-derived query ("/app.js?v=<hash>").
//
// The interface ships inside the binary, but the browser has no way to tell
// one build's app.js from the next: the embedded files have no modification
// time, so they are served without Last-Modified or ETag. A browser that
// cached a bundle from an earlier binary can therefore keep running old
// JavaScript after an upgrade, which looks exactly like a save that silently
// does nothing. Giving each build its own URL makes a stale bundle
// unreachable.
//
// The stamp is computed once, from the embedded bytes, so it changes only when
// the assets actually do.
func IndexHTML() []byte {
	stampedOnce.Do(func() {
		page, err := Assets.ReadFile("index.html")
		if err != nil {
			return
		}
		stamp := assetStamp()
		markup := string(page)
		for _, path := range assetPaths {
			markup = strings.ReplaceAll(markup, `"/`+path+`"`, `"/`+path+`?v=`+stamp+`"`)
		}
		stampedIndex = []byte(markup)
	})
	return stampedIndex
}

// assetStamp hashes the embedded assets so any content change produces a new
// query value.
func assetStamp() string {
	hash := sha256.New()
	for _, path := range assetPaths {
		if data, err := Assets.ReadFile(path); err == nil {
			_, _ = hash.Write(data)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)[:8])
}
