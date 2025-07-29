package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/XLESSGo/XLESS/app/internal/forwarding"
	"github.com/XLESSGo/XLESS/app/internal/http"
	"github.com/XLESSGo/XLESS/app/internal/proxymux"
	"github.com/XLESSGo/XLESS/app/internal/redirect"
	"github.com/XLESSGo/XLESS/app/internal/sockopts"
	"github.com/XLESSGo/XLESS/app/internal/socks5"
	"github.com/XLESSGo/XLESS/app/internal/tproxy"
	"github.com/XLESSGo/XLESS/app/internal/tun"
	"github.com/XLESSGo/XLESS/app/internal/url"
	"github.com/XLESSGo/XLESS/app/internal/utils"
	"github.com/XLESSGo/XLESS/core/client"
	"github.com/XLESSGo/XLESS/extras/correctnet"
	"github.com/lucas-clemente/quic-go" // Assuming uquic uses this as its base module name
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run in client mode",
	Run: func(cmd *cobra.Command, args []string) {
		startClient()
	},
}

type clientConfigTransport struct {
	Type          string        `mapstructure:"type"`
	KeepAlive     time.Duration `mapstructure:"keepAlive"`
	TCPFastOpen   bool          `mapstructure:"tcpFastOpen"`
	TCPNoDelay    bool          `mapstructure:"tcpNoDelay"`
	TCPAutoTuneRW bool          `mapstructure:"tcpAutoTuneRW"`
	Mux           bool          `mapstructure:"mux"`
}

type clientConfigObfs struct {
	Name string `mapstructure:"name"`
	Seed string `mapstructure:"seed"`
}

type clientConfigTLS struct {
	Enable           bool     `mapstructure:"enable"`
	DisableTLS13     bool     `mapstructure:"disableTLS13"`
	InsecureSkipVerify bool     `mapstructure:"insecureSkipVerify"`
	CaCert           string   `mapstructure:"caCert"`
	Fingerprint      string   `mapstructure:"fingerprint"`
	ServerName       string   `mapstructure:"serverName"`
	CipherSuites     []string `mapstructure:"cipherSuites"`
}

type clientConfigQUIC struct {
	Enable        bool          `mapstructure:"enable"`
	IdleTimeout   time.Duration `mapstructure:"idleTimeout"`
	KeepAlive     time.Duration `mapstructure:"keepAlive"`
	EnableUQUIC   bool          `mapstructure:"enableUQUic"`    // 新增
	UQUICSpecID   quic.QUICID   `mapstructure:"uquicSpecID"` // 新增
}

type clientConfigBandwidth struct {
	MaxSend int64 `mapstructure:"maxSend"`
	MaxRecv int64 `mapstructure:"maxRecv"`
}

type socks5Config struct {
	Listen      string        `mapstructure:"listen"`
	Timeout     time.Duration `mapstructure:"timeout"`
	Auth        string        `mapstructure:"auth"`
	UDP         bool          `mapstructure:"udp"`
	UDPIdleTimeout time.Duration `mapstructure:"udpIdleTimeout"`
	TCPRedirect string        `mapstructure:"tcpRedirect"`
}

type httpConfig struct {
	Listen      string        `mapstructure:"listen"`
	Timeout     time.Duration `mapstructure:"timeout"`
	Auth        string        `mapstructure:"auth"`
	TCPRedirect string        `mapstructure:"tcpRedirect"`
}

type tcpForwardingEntry struct {
	Listen  string `mapstructure:"listen"`
	Remote  string `mapstructure:"remote"`
	Sniff   bool   `mapstructure:"sniff"`
	Timeout string `mapstructure:"timeout"`
}

type udpForwardingEntry struct {
	Listen  string `mapstructure:"listen"`
	Remote  string `mapstructure:"remote"`
	Timeout string `mapstructure:"timeout"`
}

type tcpTProxyConfig struct {
	Listen        string        `mapstructure:"listen"`
	Timeout       time.Duration `mapstructure:"timeout"`
	Sniff         bool          `mapstructure:"sniff"`
	AllowInsecure bool          `mapstructure:"allowInsecure"`
}

type udpTProxyConfig struct {
	Listen string `mapstructure:"listen"`
}

type tcpRedirectConfig struct {
	Listen        string        `mapstructure:"listen"`
	Timeout       time.Duration `mapstructure:"timeout"`
	Sniff         bool          `mapstructure:"sniff"`
	AllowInsecure bool          `mapstructure:"allowInsecure"`
}

type tunConfig struct {
	Name        string `mapstructure:"name"`
	LIP         string `mapstructure:"lip"`
	RIP         string `mapstructure:"rip"`
	MTU         int    `mapstructure:"mtu"`
	Routes      []string `mapstructure:"routes"`
	DNS         []string `mapstructure:"dns"`
	Sniff       bool   `mapstructure:"sniff"`
	TCPTimeout  time.Duration `mapstructure:"tcpTimeout"`
	UDPIdleTimeout time.Duration `mapstructure:"udpIdleTimeout"`
	TCPRedirect string `mapstructure:"tcpRedirect"`
}

type clientConfig struct {
	Server        string                `mapstructure:"server"`
	Auth          string                `mapstructure:"auth"`
	Transport     clientConfigTransport `mapstructure:"transport"`
	Obfs          clientConfigObfs      `mapstructure:"obfs"`
	TLS           clientConfigTLS       `mapstructure:"tls"`
	QUIC          clientConfigQUIC      `mapstructure:"quic"`
	Bandwidth     clientConfigBandwidth `mapstructure:"bandwidth"`
	FastOpen      bool                  `mapstructure:"fastOpen"`
	Lazy          bool                  `mapstructure:"lazy"`
	SOCKS5        *socks5Config         `mapstructure:"socks5"`
	HTTP          *httpConfig           `mapstructure:"http"`
	TCPForwarding []tcpForwardingEntry  `mapstructure:"tcpForwarding"`
	UDPForwarding []udpForwardingEntry  `mapstructure:"udpForwarding"`
	TCPTProxy     *tcpTProxyConfig      `mapstructure:"tcpTProxy"`
	UDPTProxy     *udpTProxyConfig      `mapstructure:"udpTProxy"`
	TCPRedirect   *tcpRedirectConfig    `mapstructure:"tcpRedirect"`
	TUN           *tunConfig            `mapstructure:"tun"`
	DecoyURL      string                `mapstructure:"decoyURL"`
}

func (c *clientConfig) parseURI() {
	if strings.Contains(c.Server, "://") {
		u, err := url.Parse(c.Server)
		if err != nil {
			return
		}

		if u.Scheme != "xless" {
			return
		}

		if u.User != nil {
			c.Auth = u.User.String()
		}

		if u.Host != "" {
			c.Server = u.Host
		}

		q := u.Query
		if q.Has("transport.type") {
			c.Transport.Type = q.Get("transport.type")
		}
		if q.Has("transport.keepAlive") {
			v, err := time.ParseDuration(q.Get("transport.keepAlive"))
			if err == nil {
				c.Transport.KeepAlive = v
			}
		}
		if q.Has("transport.tcpFastOpen") {
			v, err := strconv.ParseBool(q.Get("transport.tcpFastOpen"))
			if err == nil {
				c.Transport.TCPFastOpen = v
			}
		}
		if q.Has("transport.tcpNoDelay") {
			v, err := strconv.ParseBool(q.Get("transport.tcpNoDelay"))
			if err == nil {
				c.Transport.TCPNoDelay = v
			}
		}
		if q.Has("transport.tcpAutoTuneRW") {
			v, err := strconv.ParseBool(q.Get("transport.tcpAutoTuneRW"))
			if err == nil {
				c.Transport.TCPAutoTuneRW = v
			}
		}
		if q.Has("transport.mux") {
			v, err := strconv.ParseBool(q.Get("transport.mux"))
			if err == nil {
				c.Transport.Mux = v
			}
		}

		if q.Has("obfs.name") {
			c.Obfs.Name = q.Get("obfs.name")
		}
		if q.Has("obfs.seed") {
			c.Obfs.Seed = q.Get("obfs.seed")
		}

		if q.Has("tls.enable") {
			v, err := strconv.ParseBool(q.Get("tls.enable"))
			if err == nil {
				c.TLS.Enable = v
			}
		}
		if q.Has("tls.disableTLS13") {
			v, err := strconv.ParseBool(q.Get("tls.disableTLS13"))
			if err == nil {
				c.TLS.DisableTLS13 = v
			}
		}
		if q.Has("tls.insecureSkipVerify") {
			v, err := strconv.ParseBool(q.Get("tls.insecureSkipVerify"))
			if err == nil {
				c.TLS.InsecureSkipVerify = v
			}
		}
		if q.Has("tls.caCert") {
			c.TLS.CaCert = q.Get("tls.caCert")
		}
		if q.Has("tls.fingerprint") {
			c.TLS.Fingerprint = q.Get("tls.fingerprint")
		}
		if q.Has("tls.serverName") {
			c.TLS.ServerName = q.Get("tls.serverName")
		}
		if q.Has("tls.cipherSuites") {
			c.TLS.CipherSuites = strings.Split(q.Get("tls.cipherSuites"), ",")
		}

		if q.Has("quic.enable") {
			v, err := strconv.ParseBool(q.Get("quic.enable"))
			if err == nil {
				c.QUIC.Enable = v
			}
		}
		if q.Has("quic.idleTimeout") {
			v, err := time.ParseDuration(q.Get("quic.idleTimeout"))
			if err == nil {
				c.QUIC.IdleTimeout = v
			}
		}
		if q.Has("quic.keepAlive") {
			v, err := time.ParseDuration(q.Get("quic.keepAlive"))
			if err == nil {
				c.QUIC.KeepAlive = v
			}
		}
		if q.Has("quic.enableUQUIC") {
			v, err := strconv.ParseBool(q.Get("quic.enableUQUIC"))
			if err == nil {
				c.QUIC.EnableUQUIC = v
			}
		}
		if q.Has("quic.uquicSpecID") {
			v, err := strconv.Atoi(q.Get("quic.uquicSpecID"))
			if err == nil {
				c.QUIC.UQUICSpecID = quic.QUICID(v) // Convert int to quic.QUICID
			}
		}

		if q.Has("bandwidth.maxSend") {
			v, err := strconv.ParseInt(q.Get("bandwidth.maxSend"), 10, 64)
			if err == nil {
				c.Bandwidth.MaxSend = v
			}
		}
		if q.Has("bandwidth.maxRecv") {
			v, err := strconv.ParseInt(q.Get("bandwidth.maxRecv"), 10, 64)
			if err == nil {
				c.Bandwidth.MaxRecv = v
			}
		}

		if q.Has("fastOpen") {
			v, err := strconv.ParseBool(q.Get("fastOpen"))
			if err == nil {
				c.FastOpen = v
			}
		}
		if q.Has("lazy") {
			v, err := strconv.ParseBool(q.Get("lazy"))
			if err == nil {
				c.Lazy = v
			}
		}
		if q.Has("decoyURL") {
			c.DecoyURL = q.Get("decoyURL")
		}
	}
}

func (c *clientConfig) fillServerAddr(hyConfig *client.Config) error {
	host, portStr, err := net.SplitHostPort(c.Server)
	if err != nil {
		host = c.Server
		portStr = "8443"
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return configError{Field: "server", Err: err}
	}
	hyConfig.ServerAddr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return nil
}

func (c *clientConfig) fillConnFactory(hyConfig *client.Config) error {
	switch c.Transport.Type {
	case "", "tcp":
		hyConfig.ConnFactory = &client.TCPConnFactory{
			TCPKeepAlive:  c.Transport.KeepAlive,
			TCPFastOpen:   c.Transport.TCPFastOpen,
			TCPNoDelay:    c.Transport.TCPNoDelay,
			TCPAutoTuneRW: c.Transport.TCPAutoTuneRW,
			Mux:           c.Transport.Mux,
		}
	case "wss", "ws":
		hyConfig.ConnFactory = &client.WSConnFactory{
			TLS: c.TLS.Enable,
			Host: func() string {
				host, _, _ := net.SplitHostPort(c.Server)
				return host
			}(),
			Path:      "/ws",
			KeepAlive: c.Transport.KeepAlive,
			Mux:       c.Transport.Mux,
		}
	default:
		return configError{Field: "transport.type", Err: errors.New("unsupported transport type")}
	}
	return nil
}

func (c *clientConfig) fillAuth(hyConfig *client.Config) error {
	if c.Auth == "" {
		return nil
	}
	username, password, _ := strings.Cut(c.Auth, ":")
	if username == "" || password == "" {
		return configError{Field: "auth", Err: errors.New("invalid auth")}
	}
	hyConfig.Auth = &client.Auth{
		Username: username,
		Password: password,
	}
	return nil
}

func (c *clientConfig) fillTLSConfig(hyConfig *client.Config) error {
	if !c.TLS.Enable {
		hyConfig.TLSConfig = &client.TLSConfig{}
		return nil
	}
	tlsConfig := &client.TLSConfig{
		DisableTLS13:       c.TLS.DisableTLS13,
		InsecureSkipVerify: c.TLS.InsecureSkipVerify,
	}
	if c.TLS.CaCert != "" {
		certPool := x509.NewCertPool()
		cert, err := os.ReadFile(c.TLS.CaCert)
		if err != nil {
			return configError{Field: "tls.caCert", Err: err}
		}
		if !certPool.AppendCertsFromPEM(cert) {
			return configError{Field: "tls.caCert", Err: errors.New("invalid ca cert")}
		}
		tlsConfig.RootCAs = certPool
	}
	if c.TLS.ServerName != "" {
		tlsConfig.ServerName = c.TLS.ServerName
	} else {
		host, _, err := net.SplitHostPort(c.Server)
		if err == nil {
			tlsConfig.ServerName = host
		} else {
			tlsConfig.ServerName = c.Server
		}
	}
	if c.TLS.Fingerprint != "" {
		h, err := hex.DecodeString(strings.ReplaceAll(c.TLS.Fingerprint, ":", ""))
		if err != nil || len(h) != sha256.Size {
			return configError{Field: "tls.fingerprint", Err: errors.New("invalid fingerprint")}
		}
		tlsConfig.Fingerprint = h
	}
	if len(c.TLS.CipherSuites) > 0 {
		tlsConfig.CipherSuites = make([]uint16, 0, len(c.TLS.CipherSuites))
		for _, v := range c.TLS.CipherSuites {
			s, ok := utils.CipherSuiteMap[strings.ToUpper(v)]
			if !ok {
				return configError{Field: "tls.cipherSuites", Err: errors.New("unsupported cipher suite: " + v)}
			}
			tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, s)
		}
	}
	hyConfig.TLSConfig = tlsConfig
	return nil
}

func (c *clientConfig) fillQUICConfig(hyConfig *client.Config) error {
	if !c.QUIC.Enable {
		hyConfig.QUICConfig = &client.QUICConfig{}
		return nil
	}
	hyConfig.QUICConfig = &client.QUICConfig{
		IdleTimeout: c.QUIC.IdleTimeout,
		KeepAlive:   c.QUIC.KeepAlive,
	}
	return nil
}

// fillUQUICConfig fills the uQUIC related configuration into core/client.Config
func (c *clientConfig) fillUQUICConfig(hyConfig *client.Config) error {
	if c.QUIC.EnableUQUIC {
		// Ensure QUIC config is enabled if uQUIC is enabled
		if !c.QUIC.Enable {
			return configError{Field: "quic.enableUQUIC", Err: errors.New("uQUIC requires QUIC to be enabled")}
		}
		if c.QUIC.UQUICSpecID == 0 { // Check if a valid ID is provided, 0 might be a valid ID, use a better check if possible.
			logger.Warn("uQUICSpecID is not set, using default.", zap.Any("uquicSpecID", c.QUIC.UQUICSpecID))
		}
		if hyConfig.QUICConfig == nil {
			hyConfig.QUICConfig = &client.QUICConfig{}
		}
		hyConfig.QUICConfig.EnableUQUIC = c.QUIC.EnableUQUIC
		hyConfig.QUICConfig.UQUICSpecID = c.QUIC.UQUICSpecID
	}
	return nil
}

func (c *clientConfig) fillBandwidthConfig(hyConfig *client.Config) error {
	if c.Bandwidth.MaxRecv > 0 {
		hyConfig.BandwidthConfig.MaxRecv = c.Bandwidth.MaxRecv
	}
	if c.Bandwidth.MaxSend > 0 {
		hyConfig.BandwidthConfig.MaxSend = c.Bandwidth.MaxSend
	}
	return nil
}

func (c *clientConfig) fillFastOpen(hyConfig *client.Config) error {
	hyConfig.FastOpen = c.FastOpen
	return nil
}

func (c *clientConfig) fillLazy(hyConfig *client.Config) error {
	hyConfig.Lazy = c.Lazy
	return nil
}

// fillDecoyURL method provided by user for reference
func (c *clientConfig) fillDecoyURL(hyConfig *client.Config) error {
	if c.DecoyURL == "" {
		return configError{Field: "decoyURL", Err: errors.New("decoyURL is empty")}
	}
	hyConfig.DecoyURL = c.DecoyURL
	return nil
}

func (c *clientConfig) Config() (*client.Config, error) {
	c.parseURI()
	hyConfig := &client.Config{}
	fillers := []func(*client.Config) error{
		c.fillServerAddr,
		c.fillConnFactory,
		c.fillAuth,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillUQUICConfig, // 新增
		c.fillBandwidthConfig,
		c.fillFastOpen,
		c.fillLazy,
		c.fillDecoyURL,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
	return hyConfig, nil
}

func startClient() {
	c := &clientConfig{}
	if err := viper.Unmarshal(c); err != nil {
		logger.Fatal("failed to unmarshal config", zap.Error(err))
	}

	hyClient, err := c.Config()
	if err != nil {
		logger.Fatal("failed to create client config", zap.Error(err))
	}

	client, err := client.NewClient(hyClient)
	if err != nil {
		logger.Fatal("failed to create client", zap.Error(err))
	}

	if c.SOCKS5 != nil {
		s5 := &socks5.Config{
			Listen:        c.SOCKS5.Listen,
			Timeout:       c.SOCKS5.Timeout,
			Auth:          c.SOCKS5.Auth,
			UDP:           c.SOCKS5.UDP,
			UDPIdleTimeout: c.SOCKS5.UDPIdleTimeout,
			TCPRedirect:   c.SOCKS5.TCPRedirect,
			Dial:          client.Dial,
			Logger:        &socks5Logger{},
		}
		if err := socks5.NewServer(s5).Start(); err != nil {
			logger.Error("failed to start SOCKS5 server", zap.Error(err))
		}
	}

	if c.HTTP != nil {
		http := &http.Config{
			Listen:      c.HTTP.Listen,
			Timeout:     c.HTTP.Timeout,
			Auth:        c.HTTP.Auth,
			TCPRedirect: c.HTTP.TCPRedirect,
			Dial:        client.Dial,
			Logger:      &httpLogger{},
		}
		if err := http.NewServer(http).Start(); err != nil {
			logger.Error("failed to start HTTP proxy server", zap.Error(err))
		}
	}

	for _, v := range c.TCPForwarding {
		d, err := time.ParseDuration(v.Timeout)
		if err != nil {
			logger.Warn("failed to parse tcp forwarding timeout", zap.String("timeout", v.Timeout), zap.Error(err))
			continue
		}
		f := &forwarding.Config{
			Listen:  v.Listen,
			Remote:  v.Remote,
			Sniff:   v.Sniff,
			Timeout: d,
			Dial:    client.Dial,
			Logger:  &tcpForwardingLogger{},
		}
		if err := forwarding.NewTCPForwarder(f).Start(); err != nil {
			logger.Error("failed to start TCP forwarding", zap.String("listen", v.Listen), zap.Error(err))
		}
	}

	for _, v := range c.UDPForwarding {
		d, err := time.ParseDuration(v.Timeout)
		if err != nil {
			logger.Warn("failed to parse udp forwarding timeout", zap.String("timeout", v.Timeout), zap.Error(err))
			continue
		}
		f := &forwarding.Config{
			Listen:  v.Listen,
			Remote:  v.Remote,
			Timeout: d,
			Dial:    client.DialUDP,
			Logger:  &udpForwardingLogger{},
		}
		if err := forwarding.NewUDPForwarder(f).Start(); err != nil {
			logger.Error("failed to start UDP forwarding", zap.String("listen", v.Listen), zap.Error(err))
		}
	}

	if c.TCPTProxy != nil {
		t := &tproxy.Config{
			Listen:        c.TCPTProxy.Listen,
			Timeout:       c.TCPTProxy.Timeout,
			Sniff:         c.TCPTProxy.Sniff,
			AllowInsecure: c.TCPTProxy.AllowInsecure,
			Dial:          client.Dial,
			Logger:        &tcpTProxyLogger{},
		}
		if err := tproxy.NewTCPTProxy(t).Start(); err != nil {
			logger.Error("failed to start TCP TProxy", zap.Error(err))
		}
	}

	if c.UDPTProxy != nil {
		t := &tproxy.Config{
			Listen: c.UDPTProxy.Listen,
			Dial:   client.DialUDP,
			Logger: &udpTProxyLogger{},
		}
		if err := tproxy.NewUDPTProxy(t).Start(); err != nil {
			logger.Error("failed to start UDP TProxy", zap.Error(err))
		}
	}

	if c.TCPRedirect != nil {
		r := &redirect.Config{
			Listen:        c.TCPRedirect.Listen,
			Timeout:       c.TCPRedirect.Timeout,
			Sniff:         c.TCPRedirect.Sniff,
			AllowInsecure: c.TCPRedirect.AllowInsecure,
			Dial:          client.Dial,
			Logger:        &tcpRedirectLogger{},
		}
		if err := redirect.NewTCPRedirect(r).Start(); err != nil {
			logger.Error("failed to start TCP redirect", zap.Error(err))
		}
	}

	if c.TUN != nil {
		if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
			logger.Fatal("TUN mode is only supported on Linux, macOS, and Windows")
		}
		t := &tun.Config{
			Name:           c.TUN.Name,
			LIP:            c.TUN.LIP,
			RIP:            c.TUN.RIP,
			MTU:            c.TUN.MTU,
			Routes:         c.TUN.Routes,
			DNS:            c.TUN.DNS,
			Sniff:          c.TUN.Sniff,
			TCPTimeout:     c.TUN.TCPTimeout,
			UDPIdleTimeout: c.TUN.UDPIdleTimeout,
			TCPRedirect:    c.TUN.TCPRedirect,
			DialTCP:        client.Dial,
			DialUDP:        client.DialUDP,
			Logger:         &tunLogger{},
		}
		tun, err := tun.NewTUN(t)
		if err != nil {
			logger.Fatal("failed to create TUN", zap.Error(err))
		}
		tun.Start()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutting down client")
}

type socks5Logger struct{}

func (l *socks5Logger) Connect(addr net.Addr, reqAddr string) {
	logger.Debug("SOCKS5 connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *socks5Logger) Error(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("SOCKS5 closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("SOCKS5 error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *socks5Logger) UDPRequest(addr net.Addr, sessionID uint32, reqAddr net.Addr) {
	logger.Debug("SOCKS5 UDP request", zap.String("addr", addr.String()), zap.Uint32("sessionID", sessionID), zap.String("reqAddr", reqAddr.String()))
}

func (l *socks5Logger) UDPError(addr net.Addr, sessionID uint32, err error) {
	if err == nil {
		logger.Debug("SOCKS5 UDP closed", zap.String("addr", addr.String()), zap.Uint32("sessionID", sessionID))
	} else {
		logger.Warn("SOCKS5 UDP error", zap.String("addr", addr.String()), zap.Uint32("sessionID", sessionID), zap.Error(err))
	}
}

type httpLogger struct{}

func (l *httpLogger) Connect(addr net.Addr, reqAddr string) {
	logger.Debug("HTTP connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *httpLogger) Error(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("HTTP closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("HTTP error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

type tcpForwardingLogger struct{}

func (l *tcpForwardingLogger) Connect(addr, remote, reqAddr net.Addr) {
	logger.Debug("TCP forwarding connect", zap.String("addr", addr.String()), zap.String("remote", remote.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *tcpForwardingLogger) Error(addr, remote, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP forwarding closed", zap.String("addr", addr.String()), zap.String("remote", remote.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("TCP forwarding error", zap.String("addr", addr.String()), zap.String("remote", remote.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type udpForwardingLogger struct{}

func (l *udpForwardingLogger) Connect(addr, remote, reqAddr net.Addr) {
	logger.Debug("UDP forwarding connect", zap.String("addr", addr.String()), zap.String("remote", remote.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *udpForwardingLogger) Error(addr, remote, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("UDP forwarding closed", zap.String("addr", addr.String()), zap.String("remote", remote.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("UDP forwarding error", zap.String("addr", addr.String()), zap.String("remote", remote.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type tcpTProxyLogger struct{}

func (l *tcpTProxyLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("TCP transparent proxy connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *tcpTProxyLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP transparent proxy closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("TCP transparent proxy error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type udpTProxyLogger struct{}

func (l *udpTProxyLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("UDP transparent proxy connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *udpTProxyLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("UDP transparent proxy closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("UDP transparent proxy error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type tcpRedirectLogger struct{}

func (l *tcpRedirectLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("TCP redirect connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *tcpRedirectLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP redirect closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("TCP redirect error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type tunLogger struct{}

func (l *tunLogger) TCPRequest(addr, reqAddr string) {
	logger.Debug("TUN TCP request", zap.String("addr", addr), zap.String("reqAddr", reqAddr))
}

func (l *tunLogger) TCPError(addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("TUN TCP closed", zap.String("addr", addr), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("TUN TCP error", zap.String("addr", addr), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *tunLogger) UDPRequest(addr, reqAddr string) {
	logger.Debug("TUN UDP request", zap.String("addr", addr), zap.String("reqAddr", reqAddr))
}

func (l *tunLogger) UDPError(addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("TUN UDP closed", zap.String("addr", addr), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("TUN UDP error", zap.String("addr", addr), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}
