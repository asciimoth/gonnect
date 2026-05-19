// nolint
package tun

import (
	"testing"

	"github.com/asciimoth/bufpool"
)

func testDebugPool(t *testing.T) bufpool.Pool {
	t.Helper()
	pool := bufpool.NewTestDebugPool(t)
	t.Cleanup(pool.Close)
	return pool
}
