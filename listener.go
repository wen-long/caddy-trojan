package trojan

import (
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"io"
	"net"
	"os"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	"go.uber.org/zap"

	"github.com/wen-long/caddy-trojan/trojan"
	"github.com/wen-long/caddy-trojan/utils"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
	httpcaddyfile.RegisterDirective("trojan_gfw", func(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
		return []httpcaddyfile.ConfigValue{{
			Class: "listener_wrapper",
			Value: &ListenerWrapper{},
		}}, nil
	})
}

// ListenerWrapper implements an TLS wrapper that it accept connections
// from clients and check the connection with pre-defined password
// and aead cipher defined by go-shadowsocks2, and return a normal page if
// failed.
type ListenerWrapper struct {
	// Upstream is ...
	Upstream *Upstream `json:"-,omitempty"`
	// Logger is ...
	Logger *zap.Logger `json:"-,omitempty"`
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
	m.Upstream = NewUpstream(ctx.Storage(), m.Logger)
	return nil
}

// WrapListener implements caddy.ListenWrapper
func (m *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	ln := NewListener(l, m.Upstream, m.Logger)
	go ln.loop()
	return ln
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (*ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

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
	// Upstream is ...
	Upstream *Upstream
	// Logger is ...
	Logger *zap.Logger

	// return *rawConn
	conns chan net.Conn
	// close channel
	closed chan struct{}
}

// NewListener is ...
func NewListener(ln net.Listener, up *Upstream, logger *zap.Logger) *Listener {
	l := &Listener{
		Listener: ln,
		Upstream: up,
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

		go func(c net.Conn, lg *zap.Logger, up *Upstream) {
			b := make([]byte, trojan.HeaderLen)
			readCount := 0
			for {
				n, err := c.Read(b[readCount:])
				if err != nil {
					if errors.Is(err, io.EOF) {
						lg.Error(fmt.Sprintf("read prefix error: read tcp %v -> %v: read: %v", c.RemoteAddr(), c.LocalAddr(), err))
					} else {
						lg.Error(fmt.Sprintf("read prefix error: %v", err))
					}
					c.Close()
					return
				}
				readCount += n

				maybe, matched := up.MayPrefix(utils.ByteSliceToString(b[:readCount]))
				lg.Info(fmt.Sprintf("MayPrefix of readCount %v for : %s result %v, %v",
					readCount, utils.ByteSliceToString(b[:readCount]), maybe, matched))
				if !maybe {
					select {
					case <-l.closed:
						c.Close()
					default:
						l.conns <- utils.RewindConn(c, b[:readCount])
					}
					return
				} else {
					if matched {
						break
					}
				}
			}

			//guard
			if readCount != trojan.HeaderLen {
				panic("readCount != trojan.HeaderLen")
			}

			// WE ARE SAFE
			crlf := make([]byte, 2)
			_, _ = io.ReadFull(c, crlf)

			defer c.Close()
			if l.Verbose {
				lg.Info(fmt.Sprintf("handle trojan net.Conn from %v", c.RemoteAddr()))
			}

			nr, nw, err := trojan.Handle(io.Reader(c), io.Writer(c))
			if err != nil {
				lg.Error(fmt.Sprintf("handle net.Conn error: %v", err))
			}
			up.Consume(utils.ByteSliceToString(b[:trojan.HeaderLen]), nr, nw)
		}(conn, l.Logger, l.Upstream)
	}
}
