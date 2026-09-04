package task

import (
	"context"
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/licenseenrichment"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// NewLicenseEnrichmentTask returns a Task that reads .syft-licenses.json files from the scan target
// and supplements any package that has no license information with the declared licenses when the
// package PURL matches an entry in the enrichment file.
func NewLicenseEnrichmentTask() Task {
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		enrichmentMap, err := loadDirectoryLicenseEnrichments(ctx, resolver)
		if err != nil {
			log.WithFields("error", err).Debug("failed to load license enrichments from directory")
			return nil
		}
		if len(enrichmentMap) == 0 {
			return nil
		}
		applyDirectoryLicenseEnrichment(enrichmentMap, builder)
		return nil
	}
	return NewTask("license-enrichment-task", fn, pkgcataloging.PackageTag)
}

// loadDirectoryLicenseEnrichments finds all .syft-licenses.json files reachable via the resolver,
// parses them, and merges their entries into a single PURL → []pkg.License map.
func loadDirectoryLicenseEnrichments(ctx context.Context, resolver file.Resolver) (map[string][]pkg.License, error) {
	// search both at the root and in any subdirectory so no enrichment file is missed
	locations, err := resolver.FilesByGlob(
		licenseenrichment.Filename,
		"**/"+licenseenrichment.Filename,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to search for %s: %w", licenseenrichment.Filename, err)
	}

	result := make(map[string][]pkg.License)
	for _, loc := range locations {
		rc, err := resolver.FileContentsByLocation(loc)
		if err != nil || rc == nil {
			log.WithFields("path", loc.Path(), "error", err).Debug("unable to read " + licenseenrichment.Filename)
			continue
		}

		enrichmentMap, err := licenseenrichment.ParseFile(ctx, loc, rc)
		internal.CloseAndLogError(rc, loc.Path())
		if err != nil {
			log.WithFields("path", loc.Path(), "error", err).Debug("failed to parse " + licenseenrichment.Filename)
			continue
		}

		for purl, lics := range enrichmentMap {
			result[purl] = lics
		}
	}
	return result, nil
}

// applyDirectoryLicenseEnrichment atomically updates packages in the SBOM whose PURL matches
// an entry in enrichmentMap and that currently carry no license information.
// When a package is enriched its ID is recomputed; all relationships that referenced the
// old ID are updated to reference the new one.
func applyDirectoryLicenseEnrichment(enrichmentMap map[string][]pkg.License, builder sbomsync.Builder) {
	accessor := builder.(sbomsync.Accessor)

	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		// Build a map from old package ID to enriched package for every package whose
		// PURL matches an enrichment entry and that currently has no licenses.
		oldToNew := make(map[artifact.ID]pkg.Package)

		for p := range s.Artifacts.Packages.Enumerate() {
			if p.PURL == "" || !p.Licenses.Empty() {
				continue
			}
			lics, ok := enrichmentMap[p.PURL]
			if !ok {
				continue
			}

			oldID := p.ID()
			enriched := p
			enriched.Licenses = pkg.NewLicenseSet(lics...)
			enriched.SetID()
			oldToNew[oldID] = enriched

			log.WithFields("package", p.String(), "purl", p.PURL, "licenses", len(lics)).
				Debug("enriching package licenses from " + licenseenrichment.Filename)
		}

		if len(oldToNew) == 0 {
			return
		}

		// Swap out old packages for enriched ones in the collection.
		for oldID, enrichedPkg := range oldToNew {
			s.Artifacts.Packages.Delete(oldID)
			s.Artifacts.Packages.Add(enrichedPkg)
		}

		// Update any relationships whose endpoints are now under a different ID.
		for i := range s.Relationships {
			if newPkg, ok := oldToNew[s.Relationships[i].From.ID()]; ok {
				s.Relationships[i].From = newPkg
			}
			if newPkg, ok := oldToNew[s.Relationships[i].To.ID()]; ok {
				s.Relationships[i].To = newPkg
			}
		}
	})
}
