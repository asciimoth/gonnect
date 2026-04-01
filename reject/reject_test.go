package reject_test

import (
	// "context"
	// "errors"
	// "net"
	// "os"
	// "syscall"
	"testing"

	"github.com/asciimoth/gonnect/reject"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestNativeNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return &reject.Network{}
	})
}
