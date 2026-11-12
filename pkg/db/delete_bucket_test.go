package db_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

func TestConfig_DeleteMissingBuckets(t *testing.T) {
	// Incremental builds can reach cleanup without any of the temporary
	// buckets existing. Deleting a missing bucket must be a no-op so that
	// such builds succeed.
	tmpDir := t.TempDir()
	require.NoError(t, db.Init(tmpDir))
	t.Cleanup(func() { _ = db.Close() })

	dbc := db.Config{}
	assert.NoError(t, dbc.DeleteVulnerabilityIDBucket())
	assert.NoError(t, dbc.DeleteVulnerabilityDetailBucket())
	assert.NoError(t, dbc.DeleteAdvisoryDetailBucket())

	// Repeated deletes stay idempotent.
	assert.NoError(t, dbc.DeleteVulnerabilityIDBucket())
}
