package client

import (
	"crypto/x509"
	"net"
	"time"

	"github.com/XLESSGo/XLESS/core/errors"
	"github.com/XLESSGo/XLESS/core/internal/pmtud"
	"github.com/XLESSGo/uquic"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultKeepAlivePeriod     = 10 * time.Second
)

// ProtocolType 定义了客户端支持的协议类型
type ProtocolType string

const (
	ProtocolTypeDefault  ProtocolType = "default" // 默认协议类型
	ProtocolTypeAuthA    ProtocolType = "auth_a"
)

type Config struct {
	ConnFactory     ConnFactory
	ServerAddr      net.Addr
	Auth            string
	TLSConfig       TLSConfig
	QUICConfig      QUICConfig
	BandwidthConfig BandwidthConfig
	FastOpen        bool
	DecoyURL        string
	Protocol        ProtocolType
	ProtocolParam   string
	EnableUQUIC     bool
	UQUICSpecID     quic.QUICID // 类型必须为 quic.QUICID

	filled bool // whether the fields have been verified and filled

	// Add this new field to enable FakeTCP
	XLESSUseFakeTCP bool `json:"xless_use_faketcp,omitempty"`
}

func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.ConnFactory == nil {
		c.ConnFactory = &udpConnFactory{}
	}
	if c.ServerAddr == nil {
		return errors.ConfigError{Field: "ServerAddr", Reason: "must be set"}
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return errors.ConfigError{Field: "QUICConfig.MaxIdleTimeout", Reason: "must be between 4s and 120s"}
	}
	if c.QUICConfig.KeepAlivePeriod == 0 {
		c.QUICConfig.KeepAlivePeriod = defaultKeepAlivePeriod
	} else if c.QUICConfig.KeepAlivePeriod < 2*time.Second || c.QUICConfig.KeepAlivePeriod > 60*time.Second {
		return errors.ConfigError{Field: "QUICConfig.KeepAlivePeriod", Reason: "must be between 2s and 60s"}
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery

	if c.EnableUQUIC && c.UQUICSpecID == (quic.QUICID{}) {
		return errors.ConfigError{Field: "UQUICSpecID", Reason: "must be set if EnableUQUIC"}
	}

	c.filled = true
	return nil
}

type ConnFactory interface {
	New(net.Addr) (net.PacketConn, error)
}

type udpConnFactory struct{}

func (f *udpConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

// TLSConfig contains the TLS configuration fields that we want to expose to the user.
type TLSConfig struct {
	ServerName            string
	InsecureSkipVerify    bool
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	RootCAs               *x509.CertPool
}

// QUICConfig contains the QUIC configuration fields that we want to expose to the user.
type QUICConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	DisablePathMTUDiscovery        bool

}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}
