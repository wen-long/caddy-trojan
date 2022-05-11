package trojan

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/wen-long/caddy-trojan/trojan"
	"github.com/wen-long/caddy-trojan/utils"
)

func init() {
	userLists = make([]string, 0)
	caddy.RegisterModule(ListenerWrapper{})
	httpcaddyfile.RegisterDirective("trojan_gfw", func(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
		return []httpcaddyfile.ConfigValue{{
			Class: "listener_wrapper",
			Value: &ListenerWrapper{},
		}}, nil
	})
}

var userLists []string

func validateUser(user string) bool {
	if len(user) != trojan.HeaderLen {
		return false
	}
	for _, list := range userLists {
		if list == user {
			return true
		}
	}
	return false
}

// ListenerWrapper implements an TLS wrapper that it accept connections
// from clients and check the connection with pre-defined password
// and return a normal page if failed.
type ListenerWrapper struct {
	// Logger is ...
	Logger    *zap.Logger `json:"-,omitempty"`
	UserLists []string    `json:"users"`
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.trojan",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision implements caddy.Provisioner.
func (m *ListenerWrapper) Provision(ctx caddy.Context) error {
	m.Logger = ctx.Logger(m)
	return nil
}

// WrapListener implements caddy.ListenWrapper
func (m *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	ln := NewListener(l, m.Logger)
	go ln.loop()
	return ln
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (m *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		args := d.RemainingArgs()
		switch subdirective {
		case "user":
			if len(args) < 1 {
				return d.ArgErr()
			}
			for _, v := range args {
				if len(v) == 0 {
					return d.Err("empty user is not allowed")
				}
				b := sha256.Sum224([]byte(v))
				var sum224 []byte = make([]byte, sha256.Size224)
				copy(sum224, b[:])
				newUser := hex.EncodeToString(sum224)
				userLists = append(userLists, newUser)
				m.UserLists = append(m.UserLists, v)
			}
		}
	}
	return nil
}

func (m *ListenerWrapper) ValidateUser(user string) bool {
	if len(user) != trojan.HeaderLen {
		return false
	}
	for _, list := range userLists {
		if list == user {
			return true
		}
	}
	return false
}

type UserValidateFunc func(string) bool

// Interface guards
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

// Listener is ...
type Listener struct {
	Verbose bool `json:"verbose,omitempty"`

	// Listener is ...
	net.Listener
	// Logger is ...
	Logger *zap.Logger

	// return *rawConn
	conns chan net.Conn
	// close channel
	closed chan struct{}
}

// NewListener is ...
func NewListener(ln net.Listener, logger *zap.Logger) *Listener {
	l := &Listener{
		Listener: ln,
		Logger:   logger,
		conns:    make(chan net.Conn, 8),
		closed:   make(chan struct{}),
	}
	return l
}

// Accept is ...
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, os.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
}

// Close is ...
func (l *Listener) Close() error {
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
	}
	return nil
}

// loop is ...
func (l *Listener) loop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
				l.Logger.Error(fmt.Sprintf("accept net.Conn error: %v", err))
			}
			continue
		}

		go func(c net.Conn, lg *zap.Logger) {

			// h2 is difficult to re-serve like http1.1 in TLS, so we use Handshake first and give back tls.Conn ASAP
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
				if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
					l.conns <- c
					return
				}
			}

			// behave like a normal http server made by golang
			// https://github.com/golang/go/blob/19309779ac5e2f5a2fd3cbb34421dafb2855ac21/src/net/http/request.go#L1037
			r := bufio.NewReaderSize(c, trojan.HeaderLen)
			reader := textproto.NewReader(r)
			line, err := reader.ReadLine()
			if err != nil {
				lg.Error(fmt.Sprintf("textproto ReadLine error: %v", err))
				c.Close()
				return
			}

			if !validateUser(strings.TrimSpace(line)) {
				lg.Error(fmt.Sprintf("invalid header: %s", line))
				l.conns <- utils.RewindConn(c, r, line+"\r\n")
				return
			}

			defer c.Close()
			if l.Verbose {
				lg.Info(fmt.Sprintf("handle trojan net.Conn from %v", c.RemoteAddr()))
			}

			nr, nw, err := trojan.Handle(r, io.Writer(c))
			if err != nil {
				lg.Error(fmt.Sprintf("handle net.Conn error: %v", err))
			}
			// prometheus
			_, _ = nr, nw
		}(conn, l.Logger)
	}
}
