// nolint
package gonnect_test

import (
	// "context"
	// "errors"
	// "net"
	// "os"
	// "syscall"
	"testing"

	"github.com/asciimoth/gonnect"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestRejectNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return &gonnect.RejectNetwork{}
	})
}
