// nolint
package sysnet

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
)

func TestRulesInfoCopyIsIndependent(t *testing.T) {
	src := &RulesInfo{
		TunRules:     []RuleTypeInfo{{Type: "uid", Description: "user id"}},
		MatcherRules: []RuleTypeInfo{{Type: "gid", Description: "group id"}},
	}

	got := src.Copy()
	got.TunRules[0].Type = "changed"
	got.MatcherRules[0].Type = "changed"

	if src.TunRules[0].Type != "uid" {
		t.Fatalf("TunRules alias source: %+v", src.TunRules)
	}
	if src.MatcherRules[0].Type != "gid" {
		t.Fatalf("MatcherRules alias source: %+v", src.MatcherRules)
	}
}

func TestDefaultTunOptsCopyIsIndependent(t *testing.T) {
	src := &DefaultTunOpts{
		TunAddrs:  []string{"10.0.0.2/32"},
		TunRoutes: []string{"0.0.0.0/0"},
		MTU:       1400,
		DnsIP:     "10.0.0.2",
		Strict:    true,
		Exclude:   []Rule{{Type: "uid", Rule: "1000"}},
		Include:   []Rule{{Type: "gid", Rule: "100"}},
	}

	got := src.Copy()
	got.TunAddrs[0] = "10.0.0.3/32"
	got.TunRoutes[0] = "192.0.2.0/24"
	got.Exclude[0].Rule = "1001"
	got.Include[0].Rule = "101"

	if src.TunAddrs[0] != "10.0.0.2/32" ||
		src.TunRoutes[0] != "0.0.0.0/0" ||
		src.Exclude[0].Rule != "1000" ||
		src.Include[0].Rule != "100" {
		t.Fatalf("Copy aliases source: %+v", src)
	}
	if got.MTU != 1400 || got.DnsIP != "10.0.0.2" || !got.Strict {
		t.Fatalf("Copy lost scalar fields: %+v", got)
	}
}

func TestTunOptsCopyConvertsToDefaultTunOpts(t *testing.T) {
	src := &TunOpts{
		TunAddrs:  []string{"10.0.0.4/32"},
		TunRoutes: []string{"203.0.113.0/24"},
		MTU:       1300,
	}

	got := src.Copy()
	got.TunAddrs[0] = "10.0.0.5/32"
	got.TunRoutes[0] = "198.51.100.0/24"

	if src.TunAddrs[0] != "10.0.0.4/32" ||
		src.TunRoutes[0] != "203.0.113.0/24" {
		t.Fatalf("Copy aliases source: %+v", src)
	}
	if got.MTU != 1300 || got.DnsIP != "" || got.Strict ||
		got.Exclude != nil || got.Include != nil {
		t.Fatalf("Copy returned unexpected DefaultTunOpts: %+v", got)
	}
}

func TestMatchConnNilInputs(t *testing.T) {
	matcher := &fakeMatcher{}

	matched, err := MatchConn(nil, matcher)
	if err != nil || matched {
		t.Fatalf("MatchConn(nil conn) = %v, %v; want false, nil", matched, err)
	}

	matched, err = MatchConn(fakeNetConn{}, nil)
	if err != nil || matched {
		t.Fatalf(
			"MatchConn(nil matcher) = %v, %v; want false, nil",
			matched,
			err,
		)
	}
}

func TestMatchConnPassesIncomingPeerFlowToMatcher(t *testing.T) {
	matcher := &fakeMatcher{matched: true}
	conn := fakeNetConn{
		local:  &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443},
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 55123},
	}

	matched, err := MatchConn(conn, matcher)
	if err != nil {
		t.Fatalf("MatchConn() error = %v", err)
	}
	if !matched {
		t.Fatal("MatchConn() = false, want true")
	}
	if matcher.flow.Proto != "tcp" ||
		matcher.flow.LocalPort != 55123 ||
		matcher.flow.RemotePort != 443 ||
		!matcher.flow.LocalIP.Equal(net.ParseIP("192.0.2.20")) ||
		!matcher.flow.RemoteIP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf(
			"matcher flow = %#v, want reversed incoming TCP flow",
			matcher.flow,
		)
	}
}

type fakeMatcher struct {
	matched bool
	flow    sockowner.FlowTuple
}

func (*fakeMatcher) Close() error { return nil }

func (m *fakeMatcher) Match(flow sockowner.FlowTuple) (bool, error) {
	m.flow = flow
	return m.matched, nil
}

type fakeNetConn struct {
	local  net.Addr
	remote net.Addr
}

func (fakeNetConn) Read(
	[]byte,
) (int, error) {
	return 0, errors.New("unused")
}

func (fakeNetConn) Write(
	[]byte,
) (int, error) {
	return 0, errors.New("unused")
}
func (fakeNetConn) Close() error { return nil }

func (c fakeNetConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return fakeAddr("local")
}

func (c fakeNetConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return fakeAddr("remote")
}
func (fakeNetConn) SetDeadline(time.Time) error      { return nil }
func (fakeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeNetConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }
