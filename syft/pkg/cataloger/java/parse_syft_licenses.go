package java

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// SyftLicensesFilename is the name of the enrichment file that syft will look for in archives and scan directories.
const SyftLicensesFilename = ".syft-licenses.json"

// syftLicenseEnrichmentEntry represents a single entry in a .syft-licenses.json enrichment file.
type syftLicenseEnrichmentEntry struct {
	PURL     string                  `json:"purl"`
	Licenses []syftLicenseEnrichment `json:"licenses"`
}

// syftLicenseEnrichment represents a single license declared in a .syft-licenses.json enrichment file.
type syftLicenseEnrichment struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// parseSyftLicensesEnrichment parses a .syft-licenses.json file from an io.Reader and returns a
// map of PURL → []pkg.License that can be used to supplement packages lacking license information.
func parseSyftLicensesEnrichment(ctx context.Context, location file.Location, r io.Reader) (map[string][]pkg.License, error) {
	var entries []syftLicenseEnrichmentEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil, fmt.Errorf("unable to parse %s: %w", SyftLicensesFilename, err)
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

// loadArchiveLicenseEnrichment looks for a .syft-licenses.json file inside the current archive and,
// if found, parses it and returns the resulting PURL → licenses map.
func (j *archiveParser) loadArchiveLicenseEnrichment(ctx context.Context) map[string][]pkg.License {
	matches := j.fileManifest.GlobMatch(false, "**/"+SyftLicensesFilename, SyftLicensesFilename)
	if len(matches) == 0 {
		return nil
	}

	contents, err := intFile.ContentsFromZip(ctx, j.archivePath, matches...)
	if err != nil {
		log.WithFields("error", err, "archive", j.location.Path()).Debug("unable to extract " + SyftLicensesFilename + " from archive")
		return nil
	}

	result := make(map[string][]pkg.License)
	for _, match := range matches {
		content, ok := contents[match]
		if !ok {
			continue
		}
		// synthetic location pointing at the enrichment file inside the archive
		enrichmentLocation := file.NewLocationFromCoordinates(j.location.Coordinates)
		enrichmentLocation.AccessPath = j.location.Path() + ":" + match

		enrichmentMap, err := parseSyftLicensesEnrichment(ctx, enrichmentLocation, strings.NewReader(content))
		if err != nil {
			log.WithFields("error", err, "path", match).Debug("failed to parse " + SyftLicensesFilename + " from archive")
			continue
		}
		for purl, lics := range enrichmentMap {
			result[purl] = lics
		}
	}
	return result
}

// applyArchiveLicenseEnrichment supplements the given package's license set from the enrichment map
// when the package has a PURL that matches an entry and currently has no licenses. The package ID is
// re-computed when licenses are added so that downstream consumers see a consistent fingerprint.
func applyArchiveLicenseEnrichment(p *pkg.Package, enrichmentMap map[string][]pkg.License) {
	if p == nil || len(enrichmentMap) == 0 {
		return
	}
	if p.PURL == "" || !p.Licenses.Empty() {
		return
	}
	if lics, ok := enrichmentMap[p.PURL]; ok {
		p.Licenses = pkg.NewLicenseSet(lics...)
		p.SetID()
	}
}
