package java

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenseenrichment"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_parseSyftLicensesEnrichment(t *testing.T) {
	loc := file.NewLocation("/some/.syft-licenses.json")

	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantErr  bool
	}{
		{
			name: "valid single entry",
			input: `[
				{
					"purl": "pkg:maven/com.example/artifact@1.0",
					"licenses": [{"name": "Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"}]
				}
			]`,
			wantKeys: []string{"pkg:maven/com.example/artifact@1.0"},
		},
		{
			name: "multiple entries",
			input: `[
				{"purl": "pkg:maven/a/b@1.0", "licenses": [{"name": "MIT"}]},
				{"purl": "pkg:maven/c/d@2.0", "licenses": [{"name": "Apache-2.0"}]}
			]`,
			wantKeys: []string{"pkg:maven/a/b@1.0", "pkg:maven/c/d@2.0"},
		},
		{
			name:  "empty list returns empty map",
			input: `[]`,
		},
		{
			name: "entry with empty purl is skipped",
			input: `[
				{"purl": "", "licenses": [{"name": "MIT"}]}
			]`,
			wantKeys: nil,
		},
		{
			name: "entry with no valid licenses is skipped",
			input: `[
				{"purl": "pkg:maven/a/b@1.0", "licenses": []}
			]`,
			wantKeys: nil,
		},
		{
			name:    "invalid JSON returns error",
			input:   `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := licenseenrichment.ParseFile(context.Background(), loc, strings.NewReader(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			for _, key := range tt.wantKeys {
				assert.Contains(t, result, key)
				assert.NotEmpty(t, result[key])
			}
			assert.Equal(t, len(tt.wantKeys), len(result))
		})
	}
}

func Test_applyArchiveLicenseEnrichment(t *testing.T) {
	loc := file.NewLocation("/some/archive.jar:.syft-licenses.json")

	enrichmentMap := map[string][]pkg.License{
		"pkg:maven/com.example/artifact@1.0": {
			pkg.NewLicenseFromFieldsWithContext(context.Background(), "Apache-2.0", "", &loc),
		},
	}

	tests := []struct {
		name          string
		pkg           *pkg.Package
		enrichmentMap map[string][]pkg.License
		wantLicenses  bool
	}{
		{
			name: "enriches package with matching purl and no licenses",
			pkg: &pkg.Package{
				Name:    "artifact",
				Version: "1.0",
				PURL:    "pkg:maven/com.example/artifact@1.0",
			},
			enrichmentMap: enrichmentMap,
			wantLicenses:  true,
		},
		{
			name: "does not enrich package that already has licenses",
			pkg: func() *pkg.Package {
				p := &pkg.Package{
					Name:    "artifact",
					Version: "1.0",
					PURL:    "pkg:maven/com.example/artifact@1.0",
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromFieldsWithContext(context.Background(), "MIT", "", nil),
					),
				}
				return p
			}(),
			enrichmentMap: enrichmentMap,
			wantLicenses:  true, // still has MIT
		},
		{
			name: "does not enrich package with no purl",
			pkg: &pkg.Package{
				Name:    "artifact",
				Version: "1.0",
				PURL:    "",
			},
			enrichmentMap: enrichmentMap,
			wantLicenses:  false,
		},
		{
			name: "does not enrich package with non-matching purl",
			pkg: &pkg.Package{
				Name:    "other",
				Version: "1.0",
				PURL:    "pkg:maven/com.example/other@1.0",
			},
			enrichmentMap: enrichmentMap,
			wantLicenses:  false,
		},
		{
			name:          "nil enrichment map is a no-op",
			pkg:           &pkg.Package{Name: "artifact", PURL: "pkg:maven/com.example/artifact@1.0"},
			enrichmentMap: nil,
			wantLicenses:  false,
		},
		{
			name:          "nil package is a no-op",
			pkg:           nil,
			enrichmentMap: enrichmentMap,
			wantLicenses:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyArchiveLicenseEnrichment(tt.pkg, tt.enrichmentMap)
			if tt.pkg == nil {
				return
			}
			if tt.wantLicenses {
				assert.False(t, tt.pkg.Licenses.Empty(), "expected package to have licenses")
			} else {
				assert.True(t, tt.pkg.Licenses.Empty(), "expected package to have no licenses")
			}
		})
	}
}
