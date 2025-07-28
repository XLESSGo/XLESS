package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
	"math/rand"
	"io"
	"strings"

	coreErrs "github.com/XLESSGo/XLESS/core/errors"
	"github.com/XLESSGo/XLESS/core/internal/congestion"
	"github.com/XLESSGo/XLESS/core/internal/protocol"
	"github.com/XLESSGo/XLESS/core/internal/utils"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	TCP(addr string) (net.Conn, error)
	UDP() (HyUDPConn, error)
	Close() error
}

type HyUDPConn interface {
	Receive() ([]byte, string, error)
	Send([]byte, string) error
	Close() error
}

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

func NewClient(config *Config) (Client, *HandshakeInfo, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, nil, err
	}
	c := &clientImpl{
		config: config,
	}
	info, err := c.connect()
	if err != nil {
		return nil, nil, err
	}
	return c, info, nil
}

type clientImpl struct {
	config *Config

	pktConn net.PacketConn
	conn    quic.Connection

	udpSM *udpSessionManager
}

func (c *clientImpl) connect() (*HandshakeInfo, error) {
	// 1. Establish lower-level QUIC connection
	pktConn, err := c.config.ConnFactory.New(c.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:            c.config.TLSConfig.ServerName,
		InsecureSkipVerify:    c.config.TLSConfig.InsecureSkipVerify,
		VerifyPeerCertificate: c.config.TLSConfig.VerifyPeerCertificate,
		RootCAs:               c.config.TLSConfig.RootCAs,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
		DisablePathManager:             true,
	}
	var conn quic.EarlyConnection
	var rt http.RoundTripper

	if c.config.EnableUQUIC {
		// ---- 使用 uquic ----
		// 1. 获取 Spec
		quicSpec, err := quic.QUICID2Spec(c.config.UQUICSpecID)
		if err != nil {
			_ = pktConn.Close()
			return nil, coreErrs.ConnectError{Err: err}
		}
		// 2. 创建 roundTripper
		uquicRT := &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				qc, err := quic.DialEarly(ctx, pktConn, c.config.ServerAddr, tlsCfg, cfg)
				if err != nil {
					return nil, err
				}
				conn = qc
				return qc, nil
			},
		}
		rt = http3.GetURoundTripper(uquicRT, &quicSpec, nil, nil)
	} else {
		// ---- 普通 quic-go ----
		rt = &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				qc, err := quic.DialEarly(ctx, pktConn, c.config.ServerAddr, tlsCfg, cfg)
				if err != nil {
					return nil, err
				}
				conn = qc
				return qc, nil
			},
		}
	}

	// 2. Simulate browsing the decoy site (request /index.html, extract and request 2-4 linked resources in order)
	decoyURL := c.config.DecoyURL // Should be provided in Config and match the real decoy base URL.
	httpClient := &http.Client{Timeout: 4 * time.Second}

	// 2.1 Simulate browsing by requesting /index.html and extracting linked resources.
	resources, _ := SimulateWebBrowse(httpClient, decoyURL)

	// 2.2 According to spec, before authentication, pick 2-4 linked resources (or all, if not enough),
	// and request them in order, each with a random delay.
	sendAuxiliaryRequests(httpClient, resources)
	// If there are no linked resources, proceed to authentication immediately.

	// 3. Build the obfuscated authentication request (random API path/params/headers/body)
	apiPath, query := randomAPIPathAndQuery()
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme:   "https",
			Host:     protocol.URLHost,
			Path:     apiPath,
			RawQuery: query,
		},
		Header: make(http.Header),
	}
	headers, body, contentType := buildAuthRequestObfuscatedHeaders(c.config.Auth, c.config.BandwidthConfig.MaxRx)
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", contentType)

	// 4. Insert a random delay after simulated browsing, before sending authentication request
	time.Sleep(time.Duration(500+rand.Intn(1200)) * time.Millisecond)

	// 5. Send authentication request over the QUIC/HTTP3 connection
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return nil, coreErrs.ConnectError{Err: err}
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pktConn.Close()
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// 6. Authentication successful, extract response and setup congestion control
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		congestion.UseBBR(conn)
	} else {
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(conn, actualTx)
		} else {
			congestion.UseBBR(conn)
		}
	}
	_ = resp.Body.Close()

	c.pktConn = pktConn
	c.conn = conn
	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *clientImpl) openStream() (quic.Stream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string) (net.Conn, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *clientImpl) UDP() (HyUDPConn, error) {
	if c.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	return c.udpSM.NewUDP()
}

func (c *clientImpl) Close() error {
	_ = c.conn.CloseWithError(closeErrCodeOK, "")
	_ = c.pktConn.Close()
	return nil
}

var nonPermanentErrors = []error{
	quic.StreamLimitReachedError{},
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// is recoverable (listed in nonPermanentErrors) or permanent.
// Recoverable errors are returned as-is,
// permanent ones are wrapped as ClosedError.
func wrapIfConnectionClosed(err error) error {
	for _, e := range nonPermanentErrors {
		if errors.Is(err, e) {
			return err
		}
	}
	return coreErrs.ClosedError{Err: err}
}

type tcpConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, coreErrs.DialError{Message: msg}
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

type udpIOImpl struct {
	Conn quic.Connection
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}
