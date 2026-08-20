// Package protected wraps listeners with best-effort peer-owner checks.
//
// A protected listener accepts only connections whose peer owner matches at
// least one configured rule. Connections that do not match, or whose owner
// cannot be resolved, are closed internally and the listener continues waiting
// for the next connection.
//
// The owner lookup is performed by sockowner pkg.
// That lookup is intentionally best-effort and race-prone: sockets can close,
// be reused, or be shared by multiple processes while ownership information is
// being resolved.
//
// Username rules are resolved twice. Each username is resolved once when the
// protected listener is created, and again for every accepted connection. A
// username rule matches only when both resolutions return the same UID and the
// connection owner has that UID.
package protected

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sockowner"
)

var (
	_ net.Listener        = &Listener{}
	_ net.Listener        = &TCPListener{}
	_ gonnect.TCPListener = &TCPListener{}
	_ gonnect.Wrapper     = &Listener{}
	_ gonnect.Wrapper     = &TCPListener{}
)

var (
	errNilListener = errors.New("protected: nil listener")

	getIncomingConnOwner = sockowner.GetIncomingConnOwner
	lookupUser           = user.Lookup
)

// Rules controls which peer owners may connect to a protected listener.
//
// A connection is accepted when at least one UID, GID, or username rule matches
// its resolved owner. Empty rules match nothing.
type Rules struct {
	// UIDs are OS user IDs accepted from sockowner results.
	UIDs []uint32

	// GIDs are OS group IDs accepted from sockowner results.
	GIDs []uint32

	// Usernames are resolved when the protected listener is created and again
	// for each accepted connection. A username rule matches only when both
	// resolutions produce the same UID as the connection owner.
	Usernames []string
}

type usernameRule struct {
	name string
	uid  uint32
}

type currentUsernameRule struct {
	rule usernameRule
	uid  uint32
	ok   bool
}

type checker struct {
	uids      map[uint32]struct{}
	gids      map[uint32]struct{}
	usernames []usernameRule
}

func newChecker(rules Rules) (*checker, error) {
	c := &checker{
		uids: make(map[uint32]struct{}, len(rules.UIDs)),
		gids: make(map[uint32]struct{}, len(rules.GIDs)),
	}

	for _, uid := range rules.UIDs {
		c.uids[uid] = struct{}{}
	}
	for _, gid := range rules.GIDs {
		c.gids[gid] = struct{}{}
	}
	for _, name := range rules.Usernames {
		uid, err := resolveUsernameUID(name)
		if err != nil {
			return nil, err
		}
		c.usernames = append(c.usernames, usernameRule{
			name: name,
			uid:  uid,
		})
	}

	return c, nil
}

func resolveUsernameUID(name string) (uint32, error) {
	u, err := lookupUser(name)
	if err != nil {
		return 0, fmt.Errorf("protected: resolve username %q: %w", name, err)
	}

	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf(
			"protected: parse uid for username %q: %w",
			name,
			err,
		)
	}

	return uint32(uid64), nil
}

func (c *checker) allow(conn net.Conn) bool {
	owner, err := getIncomingConnOwner(conn)
	if err != nil || owner == nil {
		return false
	}

	return c.allowOwner(owner)
}

func (c *checker) allowOwner(owner *sockowner.SocketOwner) bool {
	if owner == nil {
		return false
	}

	currentUsernames := c.currentUsernameRules()

	if owner.UID != nil {
		if _, ok := c.uids[*owner.UID]; ok {
			return true
		}

		for _, current := range currentUsernames {
			if current.ok && current.uid == current.rule.uid &&
				*owner.UID == current.uid {
				return true
			}
		}
	}

	if owner.GID != nil {
		if _, ok := c.gids[*owner.GID]; ok {
			return true
		}
	}

	return false
}

func (c *checker) currentUsernameRules() []currentUsernameRule {
	if len(c.usernames) == 0 {
		return nil
	}

	current := make([]currentUsernameRule, 0, len(c.usernames))
	for _, rule := range c.usernames {
		uid, err := resolveUsernameUID(rule.name)
		current = append(current, currentUsernameRule{
			rule: rule,
			uid:  uid,
			ok:   err == nil,
		})
	}

	return current
}

// Listener is a protected net.Listener wrapper.
type Listener struct {
	net.Listener
	checker *checker
}

// NewListener wraps l with owner-based connection filtering.
func NewListener(l net.Listener, rules Rules) (net.Listener, error) {
	if l == nil {
		return nil, errNilListener
	}

	if tl, ok := l.(gonnect.TCPListener); ok {
		return NewTCPListener(tl, rules)
	}

	c, err := newChecker(rules)
	if err != nil {
		return nil, err
	}

	return &Listener{
		Listener: l,
		checker:  c,
	}, nil
}

// Accept accepts the next connection whose owner matches the listener rules.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if conn == nil {
			continue
		}
		if l.checker.allow(conn) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// GetWrapped returns the wrapped listener.
func (l *Listener) GetWrapped() any {
	return l.Listener
}

// TCPListener is a protected gonnect.TCPListener wrapper.
type TCPListener struct {
	gonnect.TCPListener
	checker *checker
}

// NewTCPListener wraps l with owner-based TCP connection filtering.
func NewTCPListener(
	l gonnect.TCPListener,
	rules Rules,
) (gonnect.TCPListener, error) {
	if l == nil {
		return nil, errNilListener
	}

	c, err := newChecker(rules)
	if err != nil {
		return nil, err
	}

	return &TCPListener{
		TCPListener: l,
		checker:     c,
	}, nil
}

// Accept accepts the next TCP connection as a net.Conn.
func (l *TCPListener) Accept() (net.Conn, error) {
	return l.AcceptTCP()
}

// AcceptTCP accepts the next TCP connection whose owner matches the listener
// rules.
func (l *TCPListener) AcceptTCP() (gonnect.TCPConn, error) {
	for {
		conn, err := l.TCPListener.AcceptTCP()
		if err != nil {
			return nil, err
		}
		if conn == nil {
			continue
		}
		if l.checker.allow(conn) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// SetDeadline sets the deadline associated with the wrapped listener.
func (l *TCPListener) SetDeadline(t time.Time) error {
	return l.TCPListener.SetDeadline(t)
}

// GetWrapped returns the wrapped TCP listener.
func (l *TCPListener) GetWrapped() any {
	return l.TCPListener
}

// Listen announces on the local network address and returns a protected
// listener. Its network and address arguments match net.Listen.
func Listen(network, address string, rules Rules) (net.Listener, error) {
	l, err := net.Listen(network, address) // nolint:noctx
	if err != nil {
		return nil, err
	}

	protected, err := NewListener(l, rules)
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	return protected, nil
}

// ListenCtx announces on the local network address and returns a protected
// listener. Its network and address arguments match net.Listen.
func ListenCtx(
	ctx context.Context,
	network, address string,
	rules Rules,
) (net.Listener, error) {
	lc := &net.ListenConfig{}
	l, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}

	protected, err := NewListener(l, rules)
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	return protected, nil
}
