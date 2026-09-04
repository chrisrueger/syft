package task

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func Test_applyDirectoryLicenseEnrichment(t *testing.T) {
	ctx := context.Background()
	loc := file.NewLocation("/.syft-licenses.json")

	makePkg := func(name, purl string, lics ...pkg.License) pkg.Package {
		p := pkg.Package{
			Name:    name,
			Version: "1.0",
			Type:    pkg.JavaPkg,
			PURL:    purl,
		}
		if len(lics) > 0 {
			p.Licenses = pkg.NewLicenseSet(lics...)
		}
		p.SetID()
		return p
	}

	apacheLic := pkg.NewLicenseFromFieldsWithContext(ctx, "Apache-2.0", "", &loc)
	mitLic := pkg.NewLicenseFromFieldsWithContext(ctx, "MIT", "", &loc)

	enrichmentMap := map[string][]pkg.License{
		"pkg:maven/com.example/a@1.0": {apacheLic},
		"pkg:maven/com.example/b@1.0": {mitLic},
	}

	t.Run("enriches packages without licenses that match the enrichment map", func(t *testing.T) {
		pkgA := makePkg("a", "pkg:maven/com.example/a@1.0")
		pkgB := makePkg("b", "pkg:maven/com.example/b@1.0")
		pkgC := makePkg("c", "pkg:maven/com.example/c@1.0") // no match

		s := &sbom.SBOM{
			Artifacts: sbom.Artifacts{
				Packages: pkg.NewCollection(pkgA, pkgB, pkgC),
			},
		}
		builder := sbomsync.NewBuilder(s)

		applyDirectoryLicenseEnrichment(enrichmentMap, builder)

		enrichedA := s.Artifacts.Packages.PackagesByName("a")
		require.Len(t, enrichedA, 1)
		assert.False(t, enrichedA[0].Licenses.Empty(), "package a should have licenses")

		enrichedB := s.Artifacts.Packages.PackagesByName("b")
		require.Len(t, enrichedB, 1)
		assert.False(t, enrichedB[0].Licenses.Empty(), "package b should have licenses")

		enrichedC := s.Artifacts.Packages.PackagesByName("c")
		require.Len(t, enrichedC, 1)
		assert.True(t, enrichedC[0].Licenses.Empty(), "package c should not have licenses")
	})

	t.Run("does not overwrite existing licenses", func(t *testing.T) {
		existingLic := pkg.NewLicenseFromFieldsWithContext(ctx, "GPL-3.0", "", &loc)
		pkgA := makePkg("a", "pkg:maven/com.example/a@1.0", existingLic)

		s := &sbom.SBOM{
			Artifacts: sbom.Artifacts{
				Packages: pkg.NewCollection(pkgA),
			},
		}
		builder := sbomsync.NewBuilder(s)

		applyDirectoryLicenseEnrichment(enrichmentMap, builder)

		enriched := s.Artifacts.Packages.PackagesByName("a")
		require.Len(t, enriched, 1)
		// still has GPL-3.0; Apache-2.0 enrichment should not have been applied
		lics := enriched[0].Licenses.ToSlice()
		require.Len(t, lics, 1)
		assert.Equal(t, "GPL-3.0-only", lics[0].SPDXExpression)
	})

	t.Run("relationships are updated when a package ID changes due to enrichment", func(t *testing.T) {
		pkgA := makePkg("a", "pkg:maven/com.example/a@1.0")
		pkgOther := makePkg("other", "pkg:maven/com.example/other@2.0")

		oldAID := pkgA.ID()

		s := &sbom.SBOM{
			Artifacts: sbom.Artifacts{
				Packages: pkg.NewCollection(pkgA, pkgOther),
			},
			Relationships: []artifact.Relationship{
				{
					From: pkgA,
					To:   pkgOther,
					Type: artifact.DependencyOfRelationship,
				},
			},
		}
		builder := sbomsync.NewBuilder(s)

		applyDirectoryLicenseEnrichment(enrichmentMap, builder)

		// The relationship should now reference the enriched package ID, not the old one
		require.Len(t, s.Relationships, 1)
		rel := s.Relationships[0]
		assert.NotEqual(t, oldAID, rel.From.ID(), "relationship should reference the enriched package ID")

		// The enriched package's ID should now appear in the collection
		enriched := s.Artifacts.Packages.PackagesByName("a")
		require.Len(t, enriched, 1)
		assert.Equal(t, enriched[0].ID(), rel.From.ID())
	})

	t.Run("empty enrichment map is a no-op", func(t *testing.T) {
		pkgA := makePkg("a", "pkg:maven/com.example/a@1.0")
		s := &sbom.SBOM{
			Artifacts: sbom.Artifacts{
				Packages: pkg.NewCollection(pkgA),
			},
		}
		builder := sbomsync.NewBuilder(s)

		applyDirectoryLicenseEnrichment(map[string][]pkg.License{}, builder)

		enriched := s.Artifacts.Packages.PackagesByName("a")
		require.Len(t, enriched, 1)
		assert.True(t, enriched[0].Licenses.Empty())
	})
}
