package sysnetdebug

import (
	"errors"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
)

type matcher struct {
	system *System
	closed bool

	rule sysnet.Rule
}

func (m *matcher) Close() error {
	m.system.mu.Lock()
	defer m.system.mu.Unlock()

	m.closed = true

	return nil
}

func (m *matcher) isClosed() bool {
	return m.closed || m.system.closed
}

func (m *matcher) Match(flow sockowner.FlowTuple) (bool, error) {
	m.system.mu.Lock()
	defer m.system.mu.Unlock()

	if m.isClosed() {
		return false, errors.New("atcher closed")
	}

	if m.system.RuleMatcher != nil {
		return m.system.RuleMatcher(m.rule, flow)
	}

	return false, nil
}
