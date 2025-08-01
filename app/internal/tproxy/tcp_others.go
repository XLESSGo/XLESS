//go:build !linux

package tproxy

import (
	"errors"
	"net"

	"github.com/XLESSGo/XLESS/core/client"
)

type TCPTProxy struct {
	HyClient    client.Client
	EventLogger TCPEventLogger
}

type TCPEventLogger interface {
	Connect(addr, reqAddr net.Addr)
	Error(addr, reqAddr net.Addr, err error)
}

func (r *TCPTProxy) ListenAndServe(laddr *net.TCPAddr) error {
	return errors.New("not supported on this platform")
}
