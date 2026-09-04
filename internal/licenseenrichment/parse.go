// Package licenseenrichment provides support for reading .syft-licenses.json enrichment files
// that supplement package license information discovered during scanning.
package licenseenrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// Filename is the enrichment file that syft looks for in archives and scan directories.
const Filename = ".syft-licenses.json"

// Entry represents a single entry in a .syft-licenses.json enrichment file.
type Entry struct {
	PURL     string    `json:"purl"`
	Licenses []License `json:"licenses"`
}

// License represents a single license declared in a .syft-licenses.json enrichment file.
type License struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// ParseFile parses a .syft-licenses.json file from an io.Reader and returns a
// map of PURL → []pkg.License suitable for supplementing packages that lack license information.
func ParseFile(ctx context.Context, location file.Location, r io.Reader) (map[string][]pkg.License, error) {
	var entries []Entry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil, fmt.Errorf("unable to parse %s: %w", Filename, err)
	}

	result := make(map[string][]pkg.License)
	for _, entry := range entries {
		if entry.PURL == "" {
			continue
		}
		var lics []pkg.License
		for _, l := range entry.Licenses {
			lic := pkg.NewLicenseFromFieldsWithContext(ctx, l.Name, l.URL, &location)
			if !lic.Empty() {
				lics = append(lics, lic)
			}
		}
		if len(lics) > 0 {
			result[entry.PURL] = lics
		}
	}
	return result, nil
}
