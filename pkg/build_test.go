package pkg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
)

const updateInterval = 12 * time.Hour

// prepareCacheDir assembles an offline vuln-list cache from the alpine,
// wolfi and photon testdata. When broken is true the alpine advisory is
// replaced by invalid JSON so the alpine source fails while the others work.
func prepareCacheDir(t *testing.T, broken bool) string {
	t.Helper()
	cacheDir := t.TempDir()

	copies := []struct {
		src string
		dst string
	}{
		{
			src: filepath.Join("vulnsrc", "alpine", "testdata", "happy", "vuln-list"),
			dst: "vuln-list",
		},
		{
			src: filepath.Join("vulnsrc", "wolfi", "testdata", "happy", "vuln-list"),
			dst: "vuln-list",
		},
		{
			src: filepath.Join("vulnsrc", "photon", "testdata", "happy", "vuln-list"),
			dst: "vuln-list",
		},
	}
	for _, c := range copies {
		copyTree(t, c.src, filepath.Join(cacheDir, c.dst))
	}

	if broken {
		brokenFile := filepath.Join("vulnsrc", "alpine", "testdata", "sad",
			"vuln-list", "alpine", "ansible.json")
		copyTree(t, brokenFile, filepath.Join(cacheDir, "vuln-list", "alpine", "ansible.json"))
	}

	return cacheDir
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	info, err := os.Stat(src)
	require.NoError(t, err)
	if !info.IsDir() {
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
		data, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dst, data, 0o644))
		return
	}
	entries, err := os.ReadDir(src)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dst, 0o755))
	for _, entry := range entries {
		copyTree(t, filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name()))
	}
}

func noStagingLeft(t *testing.T, outputDir string) {
	t.Helper()
	entries, err := os.ReadDir(outputDir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, filepath.HasPrefix(entry.Name(), ".build-"),
			"staging directory left behind: %s", entry.Name())
	}
}

// TestRunBuild_FirstBuildSuccess builds an empty output directory from the
// offline testdata and verifies artifacts are published at the standard paths.
func TestRunBuild_FirstBuildSuccess(t *testing.T) {
	cacheDir := prepareCacheDir(t, false)
	outputDir := t.TempDir()

	require.NoError(t, runBuild(buildOptions{
		cacheDir:       cacheDir,
		outputDir:      outputDir,
		targets:        []string{"alpine", "wolfi", "photon"},
		updateInterval: updateInterval,
	}))

	dbPath := db.Path(outputDir)
	metadataPath := metadata.Path(outputDir)
	require.FileExists(t, dbPath)
	require.FileExists(t, metadataPath)
	noStagingLeft(t, outputDir)

	// All three sources must be present in the published database.
	dbtest.JSONEq(t, dbPath, []string{"data-source", "alpine 3.12"}, map[string]any{
		"ID":   "alpine",
		"Name": "Alpine Secdb",
		"URL":  "https://secdb.alpinelinux.org/",
	})
	dbtest.JSONEq(t, dbPath, []string{"data-source", "wolfi"}, map[string]any{
		"ID":   "wolfi",
		"Name": "Wolfi Secdb",
		"URL":  "https://packages.wolfi.dev/os/security.json",
	})
	dbtest.JSONEq(t, dbPath, []string{"data-source", "Photon OS 3.0"}, map[string]any{
		"ID":   "photon",
		"Name": "Photon OS CVE metadata",
		"URL":  "https://packages.broadcom.com/photon/photon_cve_metadata/",
	})

	// Optimized advisory content from each source.
	dbtest.JSONEq(t, dbPath, []string{"alpine 3.12", "ansible", "CVE-2019-14904"},
		map[string]any{"FixedVersion": "2.9.3-r0"})
	dbtest.JSONEq(t, dbPath, []string{"wolfi", "binutils", "CVE-2022-38126"},
		map[string]any{"FixedVersion": "2.39-r1"})
	dbtest.JSONEq(t, dbPath, []string{"Photon OS 3.0", "apache-tomcat", "CVE-2019-0199"},
		map[string]any{"FixedVersion": "8.5.40-1.ph3"})

	// Temporary buckets must have been cleaned up.
	dbtest.NoBucket(t, dbPath, []string{"advisory-detail"})
	dbtest.NoBucket(t, dbPath, []string{"vulnerability-detail"})
	dbtest.NoBucket(t, dbPath, []string{"vulnerability-id"})

	md, err := metadata.NewClient(outputDir).Get()
	require.NoError(t, err)
	assert.Equal(t, db.SchemaVersion, md.Version)
	assert.False(t, md.UpdatedAt.IsZero())
	// UpdatedAt and NextUpdate are read from the clock in separate calls, so
	// compare the interval rather than exact timestamps.
	assert.GreaterOrEqual(t, md.NextUpdate.Sub(md.UpdatedAt), updateInterval-time.Second)
	assert.LessOrEqual(t, md.NextUpdate.Sub(md.UpdatedAt), updateInterval+time.Second)
}

// TestRunBuild_FirstBuildFailure verifies that a failed first build leaves no
// trivy.db or metadata.json behind.
func TestRunBuild_FirstBuildFailure(t *testing.T) {
	cacheDir := prepareCacheDir(t, true)
	outputDir := t.TempDir()

	err := runBuild(buildOptions{
		cacheDir:       cacheDir,
		outputDir:      outputDir,
		targets:        []string{"alpine"},
		updateInterval: updateInterval,
	})
	require.ErrorContains(t, err, "build error")

	noStagingLeft(t, outputDir)
	assert.NoFileExists(t, db.Path(outputDir))
	assert.NoFileExists(t, metadata.Path(outputDir))
}

// TestRunBuild_FailureKeepsPreviousArtifacts verifies atomicity: a broken
// source must not modify the trivy.db or metadata.json of a previous build.
func TestRunBuild_FailureKeepsPreviousArtifacts(t *testing.T) {
	cacheDir := prepareCacheDir(t, false)
	outputDir := t.TempDir()

	// First, successful build of all three sources.
	require.NoError(t, runBuild(buildOptions{
		cacheDir:       cacheDir,
		outputDir:      outputDir,
		targets:        []string{"alpine", "wolfi", "photon"},
		updateInterval: updateInterval,
	}))

	dbPath := db.Path(outputDir)
	metadataPath := metadata.Path(outputDir)
	previousDB, err := os.ReadFile(dbPath)
	require.NoError(t, err)
	previousMetadata, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	// Then a broken rebuild. It must fail and leave the artifacts byte-identical.
	brokenCacheDir := prepareCacheDir(t, true)
	err = runBuild(buildOptions{
		cacheDir:       brokenCacheDir,
		outputDir:      outputDir,
		targets:        []string{"alpine"},
		updateInterval: updateInterval,
	})
	require.ErrorContains(t, err, "build error")

	noStagingLeft(t, outputDir)
	currentDB, err := os.ReadFile(dbPath)
	require.NoError(t, err)
	assert.Equal(t, previousDB, currentDB, "trivy.db must be untouched after a failed build")

	currentMetadata, err := os.ReadFile(metadataPath)
	require.NoError(t, err)
	assert.Equal(t, previousMetadata, currentMetadata, "metadata.json must be untouched after a failed build")

	// The previous build's data is still readable.
	dbtest.JSONEq(t, dbPath, []string{"alpine 3.12", "ansible", "CVE-2019-14904"},
		map[string]any{"FixedVersion": "2.9.3-r0"})
	dbtest.JSONEq(t, dbPath, []string{"wolfi", "binutils", "CVE-2022-38126"},
		map[string]any{"FixedVersion": "2.39-r1"})
	dbtest.JSONEq(t, dbPath, []string{"Photon OS 3.0", "apache-tomcat", "CVE-2019-0199"},
		map[string]any{"FixedVersion": "8.5.40-1.ph3"})
}

// TestRunBuild_Incremental verifies that an incremental build keeps the data
// of sources that are not rebuilt in this run and refreshes the rebuilt one.
func TestRunBuild_Incremental(t *testing.T) {
	cacheDir := prepareCacheDir(t, false)
	outputDir := t.TempDir()

	// Full build first.
	require.NoError(t, runBuild(buildOptions{
		cacheDir:       cacheDir,
		outputDir:      outputDir,
		targets:        []string{"alpine", "wolfi", "photon"},
		updateInterval: updateInterval,
	}))
	dbPath := db.Path(outputDir)

	// Rebuild only wolfi. The alpine and photon data must survive.
	require.NoError(t, runBuild(buildOptions{
		cacheDir:       cacheDir,
		outputDir:      outputDir,
		targets:        []string{"wolfi"},
		updateInterval: updateInterval,
	}))

	require.FileExists(t, dbPath)
	require.FileExists(t, metadata.Path(outputDir))
	noStagingLeft(t, outputDir)

	// Rebuilt source is present.
	dbtest.JSONEq(t, dbPath, []string{"wolfi", "binutils", "CVE-2022-38126"},
		map[string]any{"FixedVersion": "2.39-r1"})

	// Sources not rebuilt in this run are retained from the previous database.
	dbtest.JSONEq(t, dbPath, []string{"alpine 3.12", "ansible", "CVE-2019-14904"},
		map[string]any{"FixedVersion": "2.9.3-r0"})
	dbtest.JSONEq(t, dbPath, []string{"Photon OS 3.0", "apache-tomcat", "CVE-2019-0199"},
		map[string]any{"FixedVersion": "8.5.40-1.ph3"})
	dbtest.JSONEq(t, dbPath, []string{"data-source", "alpine 3.12"}, map[string]any{
		"ID":   "alpine",
		"Name": "Alpine Secdb",
		"URL":  "https://secdb.alpinelinux.org/",
	})
	dbtest.JSONEq(t, dbPath, []string{"data-source", "Photon OS 3.0"}, map[string]any{
		"ID":   "photon",
		"Name": "Photon OS CVE metadata",
		"URL":  "https://packages.broadcom.com/photon/photon_cve_metadata/",
	})

	// Temporary buckets must still be cleaned up in an incremental run.
	dbtest.NoBucket(t, dbPath, []string{"advisory-detail"})
	dbtest.NoBucket(t, dbPath, []string{"vulnerability-detail"})
	dbtest.NoBucket(t, dbPath, []string{"vulnerability-id"})
}

// TestRunBuild_IncrementalFailure verifies that a failed incremental build
// leaves the previous database, including the sources not rebuilt, untouched.
func TestRunBuild_IncrementalFailure(t *testing.T) {
	cacheDir := prepareCacheDir(t, false)
	outputDir := t.TempDir()

	require.NoError(t, runBuild(buildOptions{
		cacheDir:       cacheDir,
		outputDir:      outputDir,
		targets:        []string{"alpine", "wolfi", "photon"},
		updateInterval: updateInterval,
	}))

	dbPath := db.Path(outputDir)
	previousDB, err := os.ReadFile(dbPath)
	require.NoError(t, err)
	previousMetadata, err := os.ReadFile(metadata.Path(outputDir))
	require.NoError(t, err)

	// A broken incremental rebuild of one source must fail atomically.
	brokenCacheDir := prepareCacheDir(t, true)
	err = runBuild(buildOptions{
		cacheDir:       brokenCacheDir,
		outputDir:      outputDir,
		targets:        []string{"alpine"},
		updateInterval: updateInterval,
	})
	require.ErrorContains(t, err, "build error")

	noStagingLeft(t, outputDir)
	currentDB, err := os.ReadFile(dbPath)
	require.NoError(t, err)
	assert.Equal(t, previousDB, currentDB)
	currentMetadata, err := os.ReadFile(metadata.Path(outputDir))
	require.NoError(t, err)
	assert.Equal(t, previousMetadata, currentMetadata)

	// The untouched previous database still holds every source.
	dbtest.JSONEq(t, dbPath, []string{"wolfi", "binutils", "CVE-2022-38126"},
		map[string]any{"FixedVersion": "2.39-r1"})
	dbtest.JSONEq(t, dbPath, []string{"Photon OS 3.0", "apache-tomcat", "CVE-2019-0199"},
		map[string]any{"FixedVersion": "8.5.40-1.ph3"})
}
