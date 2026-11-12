package pkg

import (
	"os"
	"time"

	"github.com/samber/oops"
	"github.com/urfave/cli"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
)

type buildOptions struct {
	cacheDir       string
	outputDir      string
	targets        []string
	updateInterval time.Duration
}

func build(c *cli.Context) error {
	return runBuild(buildOptions{
		cacheDir:       c.String("cache-dir"),
		outputDir:      c.String("output-dir"),
		targets:        c.StringSlice("only-update"),
		updateInterval: c.Duration("update-interval"),
	})
}

func runBuild(opts buildOptions) error {
	outputDir := opts.outputDir
	eb := oops.With("output_dir", outputDir).
		With("cache_dir", opts.cacheDir).
		With("update_interval", opts.updateInterval).
		With("targets", opts.targets)

	// Build into a staging directory so that a failed build never touches the
	// existing trivy.db or metadata.json. The staging directory is created
	// inside the output directory, so the final rename is atomic (same
	// filesystem). On success its contents replace the published files.
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return eb.Wrapf(err, "output directory create error")
	}
	stagingDir, err := os.MkdirTemp(outputDir, ".build-")
	if err != nil {
		return eb.Wrapf(err, "staging directory create error")
	}
	defer os.RemoveAll(stagingDir)

	// An incremental build must keep sources that are not rebuilt this run, so
	// the build starts from a copy of the current database. A missing database
	// (first build) simply results in an empty one. The database is copied
	// before any bbolt handle is opened, so the file on disk is guaranteed to
	// be consistent; copying a live database would risk freelist/meta pages
	// being flushed while the copy is in progress.
	dbPath := db.Path(outputDir)
	stagingDBPath := db.Path(stagingDir)
	if _, err = os.Stat(dbPath); err == nil {
		if err = copyFile(dbPath, stagingDBPath); err != nil {
			return eb.Wrapf(err, "database copy error")
		}
	} else if !os.IsNotExist(err) {
		return eb.Wrapf(err, "database stat error")
	}

	if err := db.Init(stagingDir); err != nil {
		return eb.Wrapf(err, "db initialize error")
	}
	// Make sure no global bbolt handle leaks into the next process step.
	defer db.Close()

	vdb := vulndb.New(opts.cacheDir, stagingDir, opts.updateInterval)
	if err = vdb.Build(opts.targets); err != nil {
		return eb.Wrapf(err, "build error")
	}

	// All sources were built successfully. Close the staging database before
	// publishing it, then atomically replace the previous artifacts.
	if err = db.Close(); err != nil {
		return eb.Wrapf(err, "db close error")
	}
	if err = os.Rename(stagingDBPath, dbPath); err != nil {
		return eb.Wrapf(err, "database replace error")
	}

	metadataPath := metadata.Path(outputDir)
	stagingMetadataPath := metadata.Path(stagingDir)
	if _, err = os.Stat(stagingMetadataPath); err == nil {
		if err = os.Rename(stagingMetadataPath, metadataPath); err != nil {
			return eb.Wrapf(err, "metadata replace error")
		}
	} else if !os.IsNotExist(err) {
		return eb.Wrapf(err, "metadata stat error")
	}

	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return oops.With("src", src).With("dst", dst).Wrapf(err, "file read error")
	}
	if err = os.WriteFile(dst, data, 0o644); err != nil {
		return oops.With("src", src).With("dst", dst).Wrapf(err, "file write error")
	}
	return nil
}
