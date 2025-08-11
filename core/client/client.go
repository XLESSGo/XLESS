package client

import (
	"context"
	utls "github.com/refraction-networking/utls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
	"math/rand"
	"io"
	"strings"
	"fmt"
	"bytes"
	"encoding/binary"
	"sync"
	"log"

	coreErrs "github.com/XLESSGo/XLESS/core/errors"
	"github.com/XLESSGo/XLESS/core/internal/congestion"
	protocol "github.com/XLESSGo/XLESS/core/internal/protocol"
	protocol_ext "github.com/XLESSGo/XLESS/core/protocol"
	"github.com/XLESSGo/XLESS/core/internal/utils"

	"github.com/XLESSGo/uquic"
	"github.com/XLESSGo/uquic/http3"
	uquic_congestion "github.com/XLESSGo/uquic/congestion"
	faketcp "github.com/FakeTCP/FakeTCP"
)

const (
	// closeErrCodeOK is the application error code for a graceful connection closure.
	closeErrCodeOK            = 0x100
	// closeErrCodeProtocolError indicates a protocol error during connection.
	closeErrCodeProtocolError = 0x101
)

// Client is the public interface for the client, providing methods to
// establish TCP and UDP connections over the underlying transport.
type Client interface {
	// TCP opens a new TCP-like stream to a specified address.
	TCP(addr string) (net.Conn, error)
	// UDP creates a new UDP-like session for sending and receiving datagrams.
	UDP() (HyUDPConn, error)
	// Close closes the underlying QUIC connection.
	Close() error
}

// HyUDPConn is the interface for a UDP-like session.
type HyUDPConn interface {
	// Receive reads a datagram from the session. It returns the data,
	// the address of the remote peer, and an error if one occurred.
	Receive() ([]byte, string, error)
	// Send writes a datagram to the specified remote address.
	Send([]byte, string) error
	// Close terminates the UDP session.
	Close() error
}

// HandshakeInfo holds information received during the client's handshake with the server.
type HandshakeInfo struct {
	// UDPEnabled indicates if the server supports UDP over the tunnel.
	UDPEnabled bool
	// Tx is the configured maximum transmit bandwidth (in bytes per second).
	Tx         uint64
}

// clientImpl is the concrete implementation of the Client interface.
type clientImpl struct {
	config *Config
	pktConn net.PacketConn
	conn    quic.Connection
	udpSM *udpSessionManager
	protocol protocol_ext.Protocol
}

// NewClient creates and returns a new Client instance.
// It initializes the client configuration, loads any protocol plugins,
// and initiates the connection handshake with the server.
func NewClient(config *Config) (Client, *HandshakeInfo, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, nil, err
	}
	
	var p protocol_ext.Protocol
	if config.Protocol != "" && config.Protocol != "plain" && config.Protocol != "origin" {
		var err error
		p, err = protocol_ext.NewProtocol(string(config.Protocol), config.ProtocolParam)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load protocol plugin %q: %w", config.Protocol, err)
		}
	}
	
	c := &clientImpl{
		config: config,
		protocol: p,
	}
	info, err := c.connect()
	if err != nil {
		return nil, nil, err
	}
	return c, info, nil
}

// connect establishes the QUIC connection and performs the authentication handshake.
// It handles both standard QUIC and the custom FakeTCP transport.
func (c *clientImpl) connect() (*HandshakeInfo, error) {
	var conn quic.Connection
	var rt http.RoundTripper

	// If using FakeTCP, use a custom connection and RoundTripper adapter.
	if c.config.XLESSUseFakeTCP {
		log.Println("Using FakeTCP for connection")
		tcpConn, err := faketcp.Dial(c.config.ServerAddr.String())
		if err != nil {
			return nil, coreErrs.ConnectError{Err: err}
		}
		// Wrap the FakeTCP connection with a quicAdapter to satisfy the quic.Connection interface.
		conn = newQuicAdapter(tcpConn)
		c.conn = conn
		
		// In FakeTCP mode, a custom http3.RoundTripper is needed to adapt the FakeTCP connection.
		rt = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				return conn.(quic.EarlyConnection), nil
			},
			TLSClientConfig: &utls.Config{InsecureSkipVerify: true},
		}

	} else {
		// Otherwise, use a standard QUIC connection.
		pktConn, err := c.config.ConnFactory.New(c.config.ServerAddr)
		if err != nil {
			return nil, err
		}
		c.pktConn = pktConn

		tlsConfig := &utls.Config{
			ServerName:            c.config.TLSConfig.ServerName,
			InsecureSkipVerify:    c.config.TLSConfig.InsecureSkipVerify,
			VerifyPeerCertificate: c.config.TLSConfig.VerifyPeerCertificate,
			RootCAs:               c.config.TLSConfig.RootCAs,
		}

		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
			MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
			MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
			MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
			KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
			DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
			EnableDatagrams:                true,
			DisablePathManager:             true,
		}

		// Use uQUIC if enabled, otherwise use the standard QUIC dialer.
		if c.config.EnableUQUIC {
			quicSpec, err := quic.QUICID2Spec(c.config.UQUICSpecID)
			if err != nil {
				_ = pktConn.Close()
				return nil, coreErrs.ConnectError{Err: err}
			}
			rt = &http3.RoundTripper{
				TLSClientConfig: tlsConfig,
				QUICConfig:      quicConfig,
				Dial: func(ctx context.Context, _ string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
					udpConn, ok := pktConn.(net.PacketConn)
					if !ok {
						return nil, errors.New("pktConn is not a net.PacketConn, cannot use for QUIC Dial")
					}
					ut := &quic.UTransport{
						Transport: &quic.Transport{
							Conn: udpConn,
						},
						QUICSpec: &quicSpec,
					}
					udpAddr, err := net.ResolveUDPAddr(udpConn.LocalAddr().Network(), c.config.ServerAddr.String())
					if err != nil {
						return nil, err
					}
					qc, err := ut.DialEarly(ctx, udpAddr, tlsCfg, cfg)
					if err != nil {
						return nil, err
					}
					conn = qc
					return qc, nil
				},
			}
		} else {
			rt = &http3.RoundTripper{
				TLSClientConfig: tlsConfig,
				QUICConfig:      quicConfig,
				Dial: func(ctx context.Context, _ string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
					qc, err := quic.DialEarly(ctx, pktConn, c.config.ServerAddr, tlsCfg, cfg)
					if err != nil {
						return nil, err
					}
					conn = qc
					return qc, nil
				},
			}
		}
	}

	// Perform obfuscated web browsing behavior to mask the connection.
	decoyURL := c.config.DecoyURL
	httpClient := &http.Client{Timeout: 4 * time.Second}
	resources, _ := SimulateWebBrowse(httpClient, decoyURL)
	sendAuxiliaryRequests(httpClient, resources)

	// Send the unified authentication request.
	apiPath, query := randomAPIPathAndQuery()
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host: protocol.URLHost,
			Path: apiPath,
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

	// Sleep for a random duration to further obscure the connection pattern.
	time.Sleep(time.Duration(500+rand.Intn(1200)) * time.Millisecond)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		if c.pktConn != nil {
			_ = c.pktConn.Close()
		}
		return nil, coreErrs.ConnectError{Err: err}
	}
	
	// Check the authentication status code.
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		if c.pktConn != nil {
			_ = c.pktConn.Close()
		}
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}

	// Process the authentication response and configure congestion control.
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

	c.conn = conn
	if authResp.UDPEnabled {
		// Initialize the UDP session manager if UDP is enabled by the server.
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn, Protocol: c.protocol})
	}
	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

// openStream opens a new QUIC stream.
func (c *clientImpl) openStream() (quic.Stream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	return &utils.QStream{Stream: stream}, nil
}

// TCP opens a TCP-like connection by establishing a new QUIC stream
// and sending a protocol message to the server.
func (c *clientImpl) TCP(addr string) (net.Conn, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}

	var finalAddr string = addr
	// Apply protocol obfuscation to the address if a protocol plugin is active.
	if c.protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:     "tcp_request",
			IsClient: true,
			PeerAddr: c.conn.RemoteAddr(),
			StreamID: stream.StreamID(),
		}
		modifiedAddrData, pErr := c.protocol.Obfuscate(addr, ctx)
		if pErr != nil {
			_ = stream.Close()
			return nil, fmt.Errorf("protocol obfuscation failed: %w", pErr)
		}
		finalAddr = modifiedAddrData.(string)
	}

	// Write the TCP request to the stream.
	err = protocol.WriteTCPRequest(stream, finalAddr)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}

	// If FastOpen is enabled, return a connection immediately.
	if c.config.FastOpen {
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
			Established:      false,
			protocol:         c.protocol,
			isClient:         true,
			peerAddr:         c.conn.RemoteAddr(),
			streamID:         stream.StreamID(),
		}, nil
	}

	// Read the server's TCP response to confirm the connection.
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}

	if c.protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:     "tcp_response",
			IsClient: true,
			PeerAddr: c.conn.RemoteAddr(),
			StreamID: stream.StreamID(),
		}
		_, _ = ctx, ok
	}

	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		Established:      true,
		protocol:         c.protocol,
		isClient:         true,
		peerAddr:         c.conn.RemoteAddr(),
		streamID:         stream.StreamID(),
	}, nil
}

// UDP creates a new UDP-like session. It returns an error if UDP is not enabled.
func (c *clientImpl) UDP() (HyUDPConn, error) {
	if c.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	return c.udpSM.NewUDP()
}

// Close closes the underlying QUIC connection and the packet connection if it exists.
func (c *clientImpl) Close() error {
	_ = c.conn.CloseWithError(closeErrCodeOK, "")
	if c.pktConn != nil {
		_ = c.pktConn.Close()
	}
	return nil
}

// nonPermanentErrors is a list of QUIC errors that are not considered
// "connection closed" errors for wrapping purposes.
var nonPermanentErrors = []error{
	quic.StreamLimitReachedError{},
}

// wrapIfConnectionClosed checks if the given error should be wrapped as a
// coreErrs.ClosedError.
func wrapIfConnectionClosed(err error) error {
	for _, e := range nonPermanentErrors {
		if errors.Is(err, e) {
			return err
		}
	}
	return coreErrs.ClosedError{Err: err}
}

// tcpConn is a net.Conn implementation that uses a QUIC stream as its transport.
type tcpConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
	protocol         protocol_ext.Protocol
	isClient         bool
	peerAddr         net.Addr
	streamID         quic.StreamID
}

// Read reads data from the underlying QUIC stream.
// If the connection is not yet established (FastOpen), it first waits for
// the server's response.
func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if c.protocol != nil {
			ctx := protocol_ext.ProtocolContext{
				Type:     "tcp_response",
				IsClient: c.isClient,
				PeerAddr: c.peerAddr,
				StreamID: c.streamID,
			}
			_, _ = ctx, ok
		}
		if !ok {
			return 0, coreErrs.DialError{Message: msg}
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

// Write writes data to the underlying QUIC stream.
func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

// Close closes the underlying QUIC stream.
func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

// LocalAddr returns the pseudo local address.
func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

// RemoteAddr returns the pseudo remote address.
func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

// SetDeadline sets the read and write deadlines for the stream.
func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

// SetReadDeadline sets the read deadline for the stream.
func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline for the stream.
func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

// udpIOImpl implements the UDP I/O for the UDP session manager.
type udpIOImpl struct {
	Conn quic.Connection
	Protocol protocol_ext.Protocol
}

// ReceiveMessage receives a single UDP message from the QUIC connection.
// It handles both standard QUIC datagrams and messages from the FakeTCP adapter.
func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		// Handle the FakeTCP adapter specifically.
		if adapter, ok := io.Conn.(*quicAdapter); ok {
			msg, err := adapter.ReadUDPFromStream()
			if err != nil {
				return nil, err
			}
			return &protocol.UDPMessage{
				SessionID: 0,
				Addr:      msg.Addr.String(),
				Data:      msg.Payload,
			}, nil
		}
		
		msgRaw, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msgRaw)
		if err != nil {
			// Skip malformed messages and continue listening.
			continue
		}
		
		// De-obfuscate the UDP message if a protocol plugin is active.
		if io.Protocol != nil {
			ctx := protocol_ext.ProtocolContext{
				Type:     "udp_message",
				IsClient: true,
				PeerAddr: io.Conn.RemoteAddr(),
				SessionID: udpMsg.SessionID,
			}
			modifiedUDPMsgData, pErr := io.Protocol.Deobfuscate(udpMsg, ctx)
			if pErr != nil {
				// Skip if de-obfuscation fails.
				continue
			}
			udpMsg = modifiedUDPMsgData.(*protocol.UDPMessage)
		}

		return udpMsg, nil
	}
}

// SendMessage sends a single UDP message over the QUIC connection.
// It handles both standard QUIC datagrams and the FakeTCP adapter.
func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	var finalMsg *protocol.UDPMessage = msg
	// Obfuscate the UDP message if a protocol plugin is active.
	if io.Protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:      "udp_message",
			IsClient:  true,
			PeerAddr:  io.Conn.RemoteAddr(),
			SessionID: msg.SessionID,
		}
		modifiedUDPMsgData, pErr := io.Protocol.Obfuscate(msg, ctx)
		if pErr != nil {
			return fmt.Errorf("protocol obfuscation failed: %w", pErr)
		}
		finalMsg = modifiedUDPMsgData.(*protocol.UDPMessage)
	}
	
	// Handle the FakeTCP adapter specifically.
	if adapter, ok := io.Conn.(*quicAdapter); ok {
		addr, err := net.ResolveUDPAddr("udp", finalMsg.Addr)
		if err != nil {
			return fmt.Errorf("failed to resolve UDP address: %w", err)
		}
		return adapter.SendDatagramWithAddr(finalMsg.Data, addr)
	} else {
		msgN := finalMsg.Serialize(buf)
		if msgN < 0 {
			return nil
		}
		return io.Conn.SendDatagram(buf[:msgN])
	}
}

// --- Adapters for FakeTCP ---

// quicAdapter wraps a standard net.Conn (like a FakeTCP connection) to
// partially implement the quic.Connection interface. It specifically handles
// UDP datagrams by framing them over the underlying TCP stream.
type quicAdapter struct {
	conn net.Conn
	mu   sync.Mutex
}

// newQuicAdapter creates a new quicAdapter.
func newQuicAdapter(conn net.Conn) *quicAdapter {
	return &quicAdapter{conn: conn}
}

// ReadUDPFromStream reads a full UDP message from the FakeTCP stream.
// It reads the address length, address, payload length, and payload in a
// custom framing format.
func (a *quicAdapter) ReadUDPFromStream() (*faketcp.XUDPMessage, error) {
	// Read address length (4 bytes).
	var addrLen uint32
	err := binary.Read(a.conn, binary.BigEndian, &addrLen)
	if err != nil {
		return nil, err
	}
	
	// Read the address bytes.
	addrBytes := make([]byte, addrLen)
	_, err = io.ReadFull(a.conn, addrBytes)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", string(addrBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}
	
	// Read payload length (4 bytes).
	var payloadLen uint32
	err = binary.Read(a.conn, binary.BigEndian, &payloadLen)
	if err != nil {
		return nil, err
	}
	
	// Read the payload bytes.
	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(a.conn, payload)
	if err != nil {
		return nil, err
	}
	
	return &faketcp.XUDPMessage{Addr: addr, Payload: payload}, nil
}

// WriteUDPToStream writes a UDP message to the FakeTCP stream using the
// custom framing format (addr_len, addr, payload_len, payload).
func (a *quicAdapter) WriteUDPToStream(msg *faketcp.XUDPMessage) error {
	addrBytes := []byte(msg.Addr.String())
	payloadBytes := msg.Payload
	
	var buffer bytes.Buffer
	// Write address length.
	binary.Write(&buffer, binary.BigEndian, uint32(len(addrBytes)))
	// Write address.
	buffer.Write(addrBytes)
	// Write payload length.
	binary.Write(&buffer, binary.BigEndian, uint32(len(payloadBytes)))
	// Write payload.
	buffer.Write(payloadBytes)
	
	_, err := a.conn.Write(buffer.Bytes())
	return err
}

// SendDatagramWithAddr is a custom method to send a UDP datagram when the
// destination address is known, which is required for the FakeTCP adapter.
func (a *quicAdapter) SendDatagramWithAddr(payload []byte, addr net.Addr) error {
	return a.WriteUDPToStream(&faketcp.XUDPMessage{
		Addr:    addr,
		Payload: payload,
	})
}

// ReceiveDatagram reads a UDP datagram from the underlying connection.
// It retrieves the datagram from the framed message.
func (a *quicAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	msg, err := a.ReadUDPFromStream()
	if err != nil {
		return nil, err
	}
	return msg.Payload, nil
}

// SendDatagram attempts to send a datagram without an explicit address.
// This is not supported by the FakeTCP adapter, so it returns an error.
func (a *quicAdapter) SendDatagram(b []byte) error {
	return fmt.Errorf("address required for FakeTCP datagram, use SendDatagramWithAddr")
}

// The following methods are part of the quic.Connection interface but are
// not implemented or supported by the FakeTCP adapter, so they return errors.

func (a *quicAdapter) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	return a.OpenStream()
}

func (a *quicAdapter) OpenStream() (quic.Stream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

func (a *quicAdapter) AcceptStream(ctx context.Context) (quic.Stream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

func (a *quicAdapter) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

func (a *quicAdapter) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

func (a *quicAdapter) OpenUniStream() (quic.SendStream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

// HandshakeComplete returns a context that is not canceled, as the handshake
// is not performed in the same way with this adapter.
func (a *quicAdapter) HandshakeComplete() context.Context {
	return context.Background()
}

// ConnectionState returns a dummy connection state.
func (a *quicAdapter) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

// CloseWithError closes the underlying connection.
func (a *quicAdapter) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	return a.conn.Close()
}

// Context returns a background context.
func (a *quicAdapter) Context() context.Context {
	return context.Background()
}

// RemoteAddr returns the remote address of the underlying connection.
func (a *quicAdapter) RemoteAddr() net.Addr {
	return a.conn.RemoteAddr()
}

// LocalAddr returns the local address of the underlying connection.
func (a *quicAdapter) LocalAddr() net.Addr {
	return a.conn.LocalAddr()
}

// SetCongestionControl is a no-op as FakeTCP does not support this.
func (a *quicAdapter) SetCongestionControl(cc uquic_congestion.CongestionControl) {
	// FakeTCP has no built-in congestion control; this is a no-op.
}

func (a *quicAdapter) OpenEarlyStream() (quic.Stream, error) {
	return nil, fmt.Errorf("OpenEarlyStream not implemented for FakeTCP adapter")
}
func (a *quicAdapter) OpenEarlyStreamSync(ctx context.Context) (quic.Stream, error) {
	return nil, fmt.Errorf("OpenEarlyStreamSync not implemented for FakeTCP adapter")
}
func (a *quicAdapter) OpenEarlyUniStream() (quic.SendStream, error) {
	return nil, fmt.Errorf("OpenEarlyUniStream not implemented for FakeTCP adapter")
}
func (a *quicAdapter) OpenEarlyUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	return nil, fmt.Errorf("OpenEarlyUniStreamSync not implemented for FakeTCP adapter")
}
func (a *quicAdapter) EarlyConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

// Close is an alias for CloseWithError, closing the underlying connection.
func (a *quicAdapter) Close() error {
	return a.conn.Close()
}
