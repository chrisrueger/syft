package java

import (
	"context"
	"strings"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/licenseenrichment"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// loadArchiveLicenseEnrichment looks for a .syft-licenses.json file inside the current archive and,
// if found, parses it and returns the resulting PURL → licenses map.
func (j *archiveParser) loadArchiveLicenseEnrichment(ctx context.Context) map[string][]pkg.License {
	matches := j.fileManifest.GlobMatch(false, "**/"+licenseenrichment.Filename, licenseenrichment.Filename)
	if len(matches) == 0 {
		return nil
	}

	contents, err := intFile.ContentsFromZip(ctx, j.archivePath, matches...)
	if err != nil {
		log.WithFields("error", err, "archive", j.location.Path()).Debug("unable to extract " + licenseenrichment.Filename + " from archive")
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

		enrichmentMap, err := licenseenrichment.ParseFile(ctx, enrichmentLocation, strings.NewReader(content))
		if err != nil {
			log.WithFields("error", err, "path", match).Debug("failed to parse " + licenseenrichment.Filename + " from archive")
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
