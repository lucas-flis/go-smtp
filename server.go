package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

var ErrServerClosed = errors.New("smtp: server already closed")

// Logger interface is used by Server to report unexpected internal errors.
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// A SMTP server.
type Server struct {
	// The type of network, "tcp" or "unix".
	Network string
	// TCP or Unix address to listen on.
	Addr string
	// The server TLS configuration.
	TLSConfig *tls.Config
	// Enable LMTP mode, as defined in RFC 2033.
	LMTP bool

	Domain            string
	MaxRecipients     int
	MaxMessageBytes   int64
	MaxLineLength     int
	AllowInsecureAuth bool
	Debug             io.Writer
	ErrorLog          Logger
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration

	// Advertise SMTPUTF8 (RFC 6531) capability.
	// Should be used only if backend supports it.
	EnableSMTPUTF8 bool

	// Advertise REQUIRETLS (RFC 8689) capability.
	// Should be used only if backend supports it.
	EnableREQUIRETLS bool

	// Advertise BINARYMIME (RFC 3030) capability.
	// Should be used only if backend supports it.
	EnableBINARYMIME bool

	// Advertise DSN (RFC 3461) capability.
	// Should be used only if backend supports it.
	EnableDSN bool

	// Advertise RRVS (RFC 7293) capability.
	// Should be used only if backend supports it.
	EnableRRVS bool

	// Advertise DELIVERBY (RFC 2852) capability.
	// Should be used only if backend supports it.
	EnableDELIVERBY bool
	// The minimum time, with seconds precision, that a client
	// may specify in the BY argument with return mode.
	// A zero value indicates no set minimum.
	// Only use if DELIVERBY is enabled.
	MinimumDeliverByTime time.Duration

	// Advertise MT-PRIORITY (RFC 6710) capability.
	// Should only be used if backend supports it.
	EnableMTPRIORITY bool
	// The priority profile mapping as defined
	// in RFC 6710 section 10.2.
	//
	// Default value of NONE to advertise no specific profile.
	MtPriorityProfile PriorityProfile

	// The server backend.
	Backend Backend

	wg   sync.WaitGroup
	done chan struct{}

	locker    sync.Mutex
	listeners []net.Listener
	conns     map[*Conn]struct{}
}

// New creates a new SMTP server.
func NewServer(be Backend) *Server {
	return &Server{
		// Doubled maximum line length per RFC 5321 (Section 4.5.3.1.6)
		MaxLineLength: 2000,

		Backend:  be,
		done:     make(chan struct{}, 1),
		ErrorLog: log.New(os.Stderr, "smtp/server ", log.LstdFlags),
		conns:    make(map[*Conn]struct{}),
	}
}

// Serve accepts incoming connections on the Listener l.
//
// Serve always closes l, and returns ErrServerClosed at once if Close or
// Shutdown was already called. Shutdown waits for Serve to return.
func (s *Server) Serve(l net.Listener) error {
	s.locker.Lock()
	select {
	case <-s.done:
		s.locker.Unlock()
		l.Close()
		return ErrServerClosed
	default:
	}
	s.listeners = append(s.listeners, l)
	// Counted like a connection, so that a connection Serve accepts while
	// Shutdown waits is added to a non-zero counter, and Shutdown waits for
	// its refusal.
	s.wg.Add(1)
	s.locker.Unlock()
	defer s.wg.Done()
	// Before wg.Done: Shutdown returns once l is closed, on a permanent
	// Accept error too.
	defer l.Close()

	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		c, err := l.Accept()
		if err != nil {
			select {
			case <-s.done:
				// we called Close()
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				s.ErrorLog.Printf("accept error: %s; retrying in %s", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}

		conn := newConn(c, s)
		if !s.track(conn) {
			// Close or Shutdown started while the connection was being
			// accepted: it is refused, not served. The listener, closed,
			// ends the loop.
			s.refuse(conn)
			continue
		}
		go func() {
			defer s.wg.Done()

			err := s.handleConn(conn)
			if err != nil {
				s.ErrorLog.Printf("error handling %v: %s", c.RemoteAddr(), err)
			}
		}()
	}
}

// track registers an accepted connection, under the lock Close and Shutdown
// hold to stop the server, so that Shutdown waits for it and Close closes it.
// It returns false once either has started: the connection must not be
// served.
func (s *Server) track(c *Conn) bool {
	s.locker.Lock()
	defer s.locker.Unlock()

	select {
	case <-s.done:
		return false
	default:
	}
	s.wg.Add(1)
	s.conns[c] = struct{}{}
	return true
}

// refuseTimeout bounds the write of the reply to a connection refused because
// the server stops; a shorter WriteTimeout bounds it instead.
const refuseTimeout = 10 * time.Second

// refuse answers a connection accepted as the server stops with 421 (RFC 5321
// section 3.8) and closes it. A TLS connection would need its handshake
// first: it is closed without a reply.
func (s *Server) refuse(c *Conn) {
	if _, isTLS := c.conn.(*tls.Conn); !isTLS {
		d := refuseTimeout
		if s.WriteTimeout != 0 && s.WriteTimeout < d {
			d = s.WriteTimeout
		}
		c.conn.SetWriteDeadline(time.Now().Add(d))
		c.text.PrintfLine("421 4.3.2 Service shutting down")
	}
	c.Close()
}

func (s *Server) handleConn(c *Conn) error {
	defer func() {
		c.Close()

		s.locker.Lock()
		delete(s.conns, c)
		s.locker.Unlock()
	}()

	if tlsConn, ok := c.conn.(*tls.Conn); ok {
		if d := s.ReadTimeout; d != 0 {
			c.conn.SetReadDeadline(time.Now().Add(d))
		}
		if d := s.WriteTimeout; d != 0 {
			c.conn.SetWriteDeadline(time.Now().Add(d))
		}
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
	}

	c.greet()

	for {
		line, err := c.readLine()
		if err == nil {
			cmd, arg, err := parseCmd(line)
			if err != nil {
				c.protocolError(501, EnhancedCode{5, 5, 2}, "Bad command")
				continue
			}

			c.handle(cmd, arg)
		} else {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if err == ErrTooLongLine {
				c.writeResponse(500, EnhancedCode{5, 4, 0}, "Too long line, closing connection")
				return nil
			}

			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				c.writeResponse(421, EnhancedCode{4, 4, 2}, "Idle timeout, bye bye")
				return nil
			}

			c.writeResponse(421, EnhancedCode{4, 4, 0}, "Connection error, sorry")
			return err
		}
	}
}

func (s *Server) network() string {
	if s.Network != "" {
		return s.Network
	}
	if s.LMTP {
		return "unix"
	}
	return "tcp"
}

// ListenAndServe listens on the network address s.Addr and then calls Serve
// to handle requests on incoming connections.
//
// If s.Addr is blank and LMTP is disabled, ":smtp" is used.
func (s *Server) ListenAndServe() error {
	network := s.network()

	addr := s.Addr
	if !s.LMTP && addr == "" {
		addr = ":smtp"
	}

	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

// ListenAndServeTLS listens on the TCP network address s.Addr and then calls
// Serve to handle requests on incoming TLS connections.
//
// If s.Addr is blank and LMTP is disabled, ":smtps" is used.
func (s *Server) ListenAndServeTLS() error {
	network := s.network()

	addr := s.Addr
	if !s.LMTP && addr == "" {
		addr = ":smtps"
	}

	l, err := tls.Listen(network, addr, s.TLSConfig)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

// Close immediately closes all active listeners and connections.
//
// Close returns any error returned from closing the server's underlying
// listener(s).
func (s *Server) Close() error {
	s.locker.Lock()
	select {
	case <-s.done:
		s.locker.Unlock()
		return ErrServerClosed
	default:
		close(s.done)
	}

	var err error
	for _, l := range s.listeners {
		if lerr := l.Close(); lerr != nil && err == nil {
			err = lerr
		}
	}

	// No connection is added once done is closed: close those registered
	// without holding the lock, which their own teardown takes.
	conns := make([]*Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.locker.Unlock()

	for _, conn := range conns {
		conn.Close()
	}

	return err
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners and then waiting indefinitely for connections to return to
// idle and then shut down, and for Serve to return.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error, otherwise it returns any
// error returned from closing the Server's underlying Listener(s).
func (s *Server) Shutdown(ctx context.Context) error {
	s.locker.Lock()
	select {
	case <-s.done:
		s.locker.Unlock()
		return ErrServerClosed
	default:
		close(s.done)
	}

	var err error
	for _, l := range s.listeners {
		if lerr := l.Close(); lerr != nil && err == nil {
			err = lerr
		}
	}
	s.locker.Unlock()

	connDone := make(chan struct{})
	go func() {
		defer close(connDone)
		s.wg.Wait()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connDone:
		return err
	}
}
