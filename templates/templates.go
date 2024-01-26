package templates

import (
	"embed"
)

//go:embed empty.docx
//go:embed empty.xlsx
//go:embed empty.pptx
var templates embed.FS

func Templates() embed.FS {
	return templates
}
