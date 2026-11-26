package webassets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var rawDist embed.FS

// DistFS returns the embedded Vue 3 production bundle rooted at dist/.
func DistFS() (fs.FS, error) {
	return fs.Sub(rawDist, "dist")
}
