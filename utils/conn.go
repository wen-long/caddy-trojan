package utils

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

// rawConn is ...
type rawConn struct {
	net.Conn
	reader     *bufio.Reader
	lineReader bytes.Reader
}

// NewRawConn is ...
func NewRawConn(conn net.Conn, reader *bufio.Reader, line string) net.Conn {
	c := &rawConn{
		Conn:   conn,
		reader: reader,
	}
	c.lineReader.Reset([]byte(line))

	return c
}

// Read is ...
func (c *rawConn) Read(b []byte) (int, error) {
	if c.lineReader.Size() == 0 {
		return c.reader.Read(b)
	} else {
		n, err := c.lineReader.Read(b)
		if errors.Is(err, io.EOF) {
			c.lineReader.Reset([]byte{})
			return n, nil
		} else {
			return n, err
		}
	}
}

// CloseWrite is ...
func (c *rawConn) CloseWrite() error {
	if cc, ok := c.Conn.(*net.TCPConn); ok {
		return cc.CloseWrite()
	}
	if cw, ok := c.Conn.(interface {
		CloseWrite() error
	}); ok {
		return cw.CloseWrite()
	}
	return errors.New("not supported")
}
