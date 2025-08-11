package server

import (
	"context"
	utls "github.com/refraction-networking/utls"
	"encoding/json"
	"io"
	"math/rand"
    "net"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"fmt"

	"github.com/XLESSGo/uquic"
	"github.com/XLESSGo/uquic/http3"
	uquic_congestion "github.com/XLESSGo/uquic/congestion" 
	"github.com/FakeTCP/FakeTCP"

	"github.com/XLESSGo/XLESS/core/internal/congestion"
	protocol "github.com/XLESSGo/XLESS/core/internal/protocol"
	protocol_ext "github.com/XLESSGo/XLESS/core/protocol"
	"github.com/XLESSGo/XLESS/core/internal/utils"
)

// Dynamic API path pool, must be the same as the client.
var commonAPIPaths = []string{
	"/api/v1/auth", "/user/login", "/oauth/token", "/session/create",
	"/api/session", "/auth/v2/login", "/web/auth/verify",
	"/api/user/validate", "/signin", "/accounts/session", "/v2/access", "/api/v3/authenticate",
}

const (
	closeErrCodeOK                  = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeTrafficLimitReached = 0x107 // HTTP3 ErrCodeExcessiveLoad
)

// Server defines the interface for the XLESS server.
type Server interface {
	Serve() error
	Close() error
}

// XListener defines an extended listener interface.
type XListener interface {
	Accept(ctx context.Context) (net.Conn, error)
	Addr() net.Addr
	Close() error
}

// quicListenerWrapper wraps a quic.Listener to implement the XListener interface.
type quicListenerWrapper struct {
	*quic.Listener
}

// Accept returns a net.Conn by wrapping the quic.Connection.
func (l *quicListenerWrapper) Accept(ctx context.Context) (net.Conn, error) {
	conn, err := l.Listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newQuicConnWrapper(conn), nil
}

// quicConnWrapper wraps quic.Connection and implements net.Conn.
type quicConnWrapper struct {
	quic.Connection
}

// newQuicConnWrapper creates a new quicConnWrapper.
func newQuicConnWrapper(conn quic.Connection) *quicConnWrapper {
	return &quicConnWrapper{Connection: conn}
}

// Close implements the net.Conn Close method.
func (c *quicConnWrapper) Close() error {
	return c.Connection.CloseWithError(closeErrCodeOK, "")
}

// Read is a placeholder for net.Conn Read, not implemented for this wrapper.
func (c *quicConnWrapper) Read(b []byte) (n int, err error) {
	return 0, fmt.Errorf("read not implemented for quicConnWrapper")
}

// Write is a placeholder for net.Conn Write, not implemented for this wrapper.
func (c *quicConnWrapper) Write(b []byte) (n int, err error) {
	return 0, fmt.Errorf("write not implemented for quicConnWrapper")
}

// SetDeadline is a placeholder for net.Conn SetDeadline.
func (c *quicConnWrapper) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a placeholder for net.Conn SetReadDeadline.
func (c *quicConnWrapper) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a placeholder for net.Conn SetWriteDeadline.
func (c *quicConnWrapper) SetWriteDeadline(t time.Time) error {
	return nil
}

// serverImpl is the concrete implementation of the Server interface.
type serverImpl struct {
	config   *Config
	listener XListener
	protocol protocol_ext.Protocol
}

// NewServer creates a new Server instance.
func NewServer(config *Config) (Server, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}

	var listener XListener
	var err error

	if config.XLESSUseFakeTCP {
		listener, err = faketcp.XListenFakeTCP(config.Conn.LocalAddr().String())
	} else {
		tlsConfig := &utls.Config{
			Certificates:   config.TLSConfig.Certificates,
			GetCertificate: config.TLSConfig.GetCertificate,
		}
		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     config.QUICConfig.InitialStreamReceiveWindow,
			MaxStreamReceiveWindow:         config.QUICConfig.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: config.QUICConfig.InitialConnectionReceiveWindow,
			MaxConnectionReceiveWindow:     config.QUICConfig.MaxConnectionReceiveWindow,
			MaxIdleTimeout:                 config.QUICConfig.MaxIdleTimeout,
			MaxIncomingStreams:             config.QUICConfig.MaxIncomingStreams,
			DisablePathMTUDiscovery:        config.QUICConfig.DisablePathMTUDiscovery,
			EnableDatagrams:                true,
			DisablePathManager:             true,
		}
		quicLis, err := quic.Listen(config.Conn, tlsConfig, quicConfig)
		if err == nil {
			listener = &quicListenerWrapper{Listener: quicLis}
		}
	}

	if err != nil {
		_ = config.Conn.Close()
		return nil, err
	}

	var p protocol_ext.Protocol
	if config.Protocol != "" && config.Protocol != "plain" && config.Protocol != "origin" {
		var err error
		p, err = protocol_ext.NewProtocol(string(config.Protocol), config.ProtocolParam)
		if err != nil {
			return nil, fmt.Errorf("failed to load protocol plugin %q: %w", config.Protocol, err)
		}
	}

	return &serverImpl{
		config:   config,
		listener: listener,
		protocol: p,
	}, nil
}

// Serve starts the server loop to accept new connections.
func (s *serverImpl) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

// Close closes the listener and underlying connection.
func (s *serverImpl) Close() error {
	err := s.listener.Close()
	_ = s.config.Conn.Close()
	return err
}

// handleClient handles a new client connection based on its type.
func (s *serverImpl) handleClient(conn net.Conn) {
	switch c := conn.(type) {
	case *quicConnWrapper:
		s.handleQUICClient(c.Connection)
	case *faketcp.XStreamConn:
		adapter := newQuicAdapter(c)
		s.handleQUICClient(adapter)
	default:
		log.Printf("Received an unknown connection type from %s", conn.RemoteAddr())
		conn.Close()
	}
}

// handleQUICClient serves an HTTP/3 server on a QUIC connection.
func (s *serverImpl) handleQUICClient(conn quic.Connection) {
	handler := newH3sHandler(s.config, conn)
	handler.protocol = s.protocol
	h3s := http3.Server{
		Handler:        handler,
		StreamHijacker: handler.ProxyStreamHijacker,
	}
	err := h3s.ServeQUICConn(conn)
	if handler.authenticated {
		if tl := s.config.TrafficLogger; tl != nil {
			tl.LogOnlineState(handler.authID, false)
		}
		if el := s.config.EventLogger; el != nil {
			el.Disconnect(conn.RemoteAddr(), handler.authID, err)
		}
	}
	_ = conn.CloseWithError(closeErrCodeOK, "")
}

// --- New types and methods to adapt FakeTCP ---

// quicAdapter wraps a FakeTCP stream to implement the quic.Connection interface.
type quicAdapter struct {
	*faketcp.XStreamConn
}

// newQuicAdapter creates a new quicAdapter.
func newQuicAdapter(conn *faketcp.XStreamConn) *quicAdapter {
	return &quicAdapter{XStreamConn: conn}
}

// ReceiveDatagram reads and reconstructs a UDP datagram from the FakeTCP stream.
func (a *quicAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	msg, err := a.XStreamConn.ReadUDPFromStream()
	if err != nil {
		return nil, err
	}
	return msg.Payload, nil
}

// SendDatagramWithAddr is a custom method to send a datagram with an address.
func (a *quicAdapter) SendDatagramWithAddr(payload []byte, addr net.Addr) error {
	return a.XStreamConn.WriteUDPToStream(&faketcp.XUDPMessage{
		Addr:    addr,
		Payload: payload,
	})
}

// SendDatagram packages and writes a UDP datagram to the FakeTCP stream.
// This method is not used directly as an address is required.
func (a *quicAdapter) SendDatagram(b []byte) error {
	return fmt.Errorf("address required for FakeTCP datagram, use SendDatagramWithAddr")
}

// OpenStreamSync is not implemented for the FakeTCP adapter.
func (a *quicAdapter) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	return a.OpenStream()
}

// OpenStream is not implemented for the FakeTCP adapter.
func (a *quicAdapter) OpenStream() (quic.Stream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

// AcceptStream is not implemented for the FakeTCP adapter.
func (a *quicAdapter) AcceptStream(ctx context.Context) (quic.Stream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

// AcceptUniStream is not implemented for the FakeTCP adapter.
func (a *quicAdapter) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

// OpenUniStreamSync is not implemented for the FakeTCP adapter.
func (a *quicAdapter) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

// OpenUniStream is not implemented for the FakeTCP adapter.
func (a *quicAdapter) OpenUniStream() (quic.SendStream, error) {
	return nil, fmt.Errorf("stream not implemented for FakeTCP adapter")
}

// HandshakeComplete is a placeholder for the handshake context.
func (a *quicAdapter) HandshakeComplete() context.Context {
	return context.Background()
}

// ConnectionState is a placeholder for the connection state.
func (a *quicAdapter) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

// CloseWithError closes the underlying FakeTCP stream.
func (a *quicAdapter) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	return a.XStreamConn.Close()
}

// Context is required by the quic.Connection interface.
func (a *quicAdapter) Context() context.Context {
	return context.Background()
}

// RemoteAddr returns the remote address of the FakeTCP stream.
func (a *quicAdapter) RemoteAddr() net.Addr {
	return a.XStreamConn.RemoteAddr()
}

// LocalAddr returns the local address of the FakeTCP stream.
func (a *quicAdapter) LocalAddr() net.Addr {
	return a.XStreamConn.LocalAddr()
}

// SetCongestionControl is a required method for the quic.Connection interface.
func (a *quicAdapter) SetCongestionControl(cc uquic_congestion.CongestionControl) error {
	// FakeTCP has no built-in congestion control; this is a no-op.
	return nil
}

// h3sHandler handles HTTP/3 requests.
type h3sHandler struct {
	config        *Config
	conn          quic.Connection
	authenticated bool
	authMutex     sync.Mutex
	authID        string
	connID        uint32 // Random ID for dumping streams
	udpSM         *udpSessionManager
	decoyProxy    *DecoyProxy
	protocol      protocol_ext.Protocol // Protocol plugin for h3sHandler
}

// newH3sHandler creates a new h3sHandler.
func newH3sHandler(config *Config, conn quic.Connection) *h3sHandler {
	return &h3sHandler{
		config:     config,
		conn:       conn,
		connID:     rand.Uint32(),
		decoyProxy: NewDecoyProxy(config.DecoyURL),
	}
}

// isObfuscatedAuthRequest determines if a request is an obfuscated authentication request.
func isObfuscatedAuthRequest(r *http.Request) bool {
	// 1. Path must be in the API path pool.
	pathOk := false
	for _, p := range commonAPIPaths {
		if r.URL.Path == p {
			pathOk = true
			break
		}
	}
	if !pathOk {
		return false
	}
	// 2. Must have an Authorization or Cookie header with a valid-looking token.
	authH := r.Header.Get("Authorization")
	cookieH := r.Header.Get("Cookie")
	if !strings.Contains(authH, "Bearer ") && !strings.Contains(cookieH, "session_id=") {
		return false
	}
	// 3. Content-Type must be application/json or application/x-www-form-urlencoded.
	ctype := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ctype, "application/json") &&
		!strings.HasPrefix(ctype, "application/x-www-form-urlencoded") {
		return false
	}
	// 4. For JSON, the body must contain a "token" field.
	if !strings.HasPrefix(ctype, "application/json") {
		return true // Skip deep check for urlencoded
	}
	bodyRaw, err := io.ReadAll(r.Body)
	if err != nil || len(bodyRaw) == 0 {
		return false
	}
	var body map[string]interface{}
	_ = json.Unmarshal(bodyRaw, &body)
	// Restore the body for other handlers.
	r.Body = io.NopCloser(strings.NewReader(string(bodyRaw)))
	_, hasToken := body["token"]
	return hasToken
}

// ServeHTTP handles HTTP requests.
func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.authMutex.Lock()
	defer h.authMutex.Unlock()

	// If not authenticated, check for an obfuscated authentication request.
	if !h.authenticated && isObfuscatedAuthRequest(r) {
		authReq := protocol.AuthRequestFromObfuscated(r)
		actualTx := authReq.Rx
		ok, id := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), authReq.Auth, actualTx)
		if ok {
			h.authenticated = true
			h.authID = id
			if h.config.IgnoreClientBandwidth {
				congestion.UseBBR(h.conn)
				actualTx = 0
			} else {
				if h.config.BandwidthConfig.MaxTx > 0 && actualTx > h.config.BandwidthConfig.MaxTx {
					actualTx = h.config.BandwidthConfig.MaxTx
				}
				if actualTx > 0 {
					congestion.UseBrutal(h.conn, actualTx)
				} else {
					congestion.UseBBR(h.conn)
				}
			}
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			if tl := h.config.TrafficLogger; tl != nil {
				tl.LogOnlineState(id, true)
			}
			if el := h.config.EventLogger; el != nil {
				el.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			if !h.config.DisableUDP {
				go func() {
					sm := newUDPSessionManager(
						&udpIOImpl{h.conn, id, h.config.TrafficLogger, h.config.RequestHook, h.config.Outbound, h.protocol},
						&udpEventLoggerImpl{h.conn, id, h.config.EventLogger},
						h.config.UDPIdleTimeout)
					h.udpSM = sm
					go sm.Run()
				}()
			}
			return
		} else {
			h.decoyProxy.ServeHTTP(w, r)
			return
		}
	}

	// If not authenticated, forward to the decoy service.
	if !h.authenticated {
		h.decoyProxy.ServeHTTP(w, r)
		return
	}

	// Already authenticated, respond to any further auth requests.
	if isObfuscatedAuthRequest(r) {
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !h.config.DisableUDP,
			Rx:         h.config.BandwidthConfig.MaxRx,
			RxAuto:     h.config.IgnoreClientBandwidth,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		return
	}

	// All other requests are handled by the MasqHandler.
	h.masqHandler(w, r)
}

// ProxyStreamHijacker handles hijacked streams for TCP proxying.
func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, id quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
	if err != nil || !h.authenticated {
		return false, nil
	}

	stream = &utils.QStream{Stream: stream}

	switch ft {
	case protocol.FrameTypeTCPRequest:
		go h.handleTCPRequest(stream)
		return true, nil
	default:
		return false, nil
	}
}

// handleTCPRequest handles a TCP proxy request on a QUIC stream.
func (h *h3sHandler) handleTCPRequest(stream quic.Stream) {
	trafficLogger := h.config.TrafficLogger
	streamStats := &StreamStats{
		AuthID:      h.authID,
		ConnID:      h.connID,
		InitialTime: time.Now(),
	}
	streamStats.State.Store(StreamStateInitial)
	streamStats.LastActiveTime.Store(time.Now())
	defer func() {
		streamStats.State.Store(StreamStateClosed)
	}()
	if trafficLogger != nil {
		trafficLogger.TraceStream(stream, streamStats)
		defer trafficLogger.UntraceStream(stream)
	}

	reqAddr, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	
	// Deobfuscate protocol fields on the server-side immediately after decryption.
	if h.protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:     "tcp_request",
			IsClient: false,
			PeerAddr: h.conn.RemoteAddr(),
			StreamID: stream.StreamID(),
		}
		modifiedReqAddrData, pErr := h.protocol.Deobfuscate(reqAddr, ctx)
		if pErr != nil {
			_ = protocol.WriteTCPResponse(stream, false, fmt.Sprintf("protocol deobfuscation failed: %s", pErr.Error()))
			_ = stream.Close()
			return
		}
		reqAddr = modifiedReqAddrData.(string)
	}
	
	streamStats.ReqAddr.Store(reqAddr)
	var putback []byte
	var hooked bool
	if h.config.RequestHook != nil {
		hooked = h.config.RequestHook.Check(false, reqAddr)
		if hooked {
			streamStats.State.Store(StreamStateHooking)
			_ = protocol.WriteTCPResponse(stream, true, "RequestHook enabled")
			putback, err = h.config.RequestHook.TCP(stream, &reqAddr)
			if err != nil {
				_ = stream.Close()
				return
			}
			streamStats.setHookedReqAddr(reqAddr)
		}
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), h.authID, reqAddr)
	}
	streamStats.State.Store(StreamStateConnecting)
	tConn, err := h.config.Outbound.TCP(reqAddr)
	if err != nil {
		if !hooked {
			_ = protocol.WriteTCPResponse(stream, false, err.Error())
		}
		_ = stream.Close()
		if h.config.EventLogger != nil {
			h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
		}
		return
	}
	if !hooked {
		_ = protocol.WriteTCPResponse(stream, true, "Connected")
	}
	streamStats.State.Store(StreamStateEstablished)
	if len(putback) > 0 {
		n, _ := tConn.Write(putback)
		streamStats.Tx.Add(uint64(n))
	}
	if trafficLogger != nil {
		err = copyTwoWayEx(h.authID, stream, tConn, trafficLogger, streamStats)
	} else {
		err = copyTwoWay(stream, tConn)
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
	}
	_ = tConn.Close()
	_ = stream.Close()
	if err == errDisconnect {
		_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
	}
}

// masqHandler handles requests for the masquerading service.
func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		http.NotFound(w, r)
	}
}

// udpIOImpl is the IO implementation for udpSessionManager with TrafficLogger support.
type udpIOImpl struct {
	Conn          quic.Connection
	AuthID        string
	TrafficLogger TrafficLogger
	RequestHook   RequestHook
	Outbound      Outbound
	Protocol      protocol_ext.Protocol
}

// ReceiveMessage receives a UDP message from the QUIC connection.
func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msgRaw, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msgRaw)
		if err != nil {
			continue
		}

		// Deobfuscate protocol fields on the server-side for received UDP packets.
		if io.Protocol != nil {
			ctx := protocol_ext.ProtocolContext{
				Type:      "udp_message",
				IsClient:  false,
				PeerAddr:  io.Conn.RemoteAddr(),
				SessionID: udpMsg.SessionID,
			}
			modifiedUDPMsgData, pErr := io.Protocol.Deobfuscate(udpMsg, ctx)
			if pErr != nil {
				continue
			}
			udpMsg = modifiedUDPMsgData.(*protocol.UDPMessage)
		}

		if io.TrafficLogger != nil {
			ok := io.TrafficLogger.LogTraffic(io.AuthID, uint64(len(udpMsg.Data)), 0)
			if !ok {
				_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
				return nil, errDisconnect
			}
		}
		return udpMsg, nil
	}
}

// SendMessage packages and sends a UDP message.
func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	if io.TrafficLogger != nil {
		ok := io.TrafficLogger.LogTraffic(io.AuthID, 0, uint64(len(msg.Data)))
		if !ok {
			_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return errDisconnect
		}
	}
	
	var finalMsg *protocol.UDPMessage = msg
	if io.Protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:      "udp_message",
			IsClient:  false,
			PeerAddr:  io.Conn.RemoteAddr(),
			SessionID: msg.SessionID,
		}
		modifiedUDPMsgData, pErr := io.Protocol.Obfuscate(msg, ctx)
		if pErr != nil {
			return fmt.Errorf("protocol obfuscation failed: %w", pErr)
		}
		finalMsg = modifiedUDPMsgData.(*protocol.UDPMessage)
	}

	// Handle FakeTCP adapter using type assertion.
	if adapter, ok := io.Conn.(*quicAdapter); ok {
		addr, err := net.ResolveUDPAddr("udp", msg.Addr)
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

// Hook is a hook for UDP traffic.
func (io *udpIOImpl) Hook(data []byte, reqAddr *string) error {
	if io.RequestHook != nil && io.RequestHook.Check(true, *reqAddr) {
		return io.RequestHook.UDP(data, reqAddr)
	}
	return nil
}

// UDP returns a UDPConn for a given address.
func (io *udpIOImpl) UDP(reqAddr string) (UDPConn, error) {
	return io.Outbound.UDP(reqAddr)
}

// udpEventLoggerImpl implements the EventLogger interface for UDP sessions.
type udpEventLoggerImpl struct {
	Conn        quic.Connection
	AuthID      string
	EventLogger EventLogger
}

// New logs a new UDP session.
func (l *udpEventLoggerImpl) New(sessionID uint32, reqAddr string) {
	if l.EventLogger != nil {
		l.EventLogger.UDPRequest(l.Conn.RemoteAddr(), l.AuthID, sessionID, reqAddr)
	}
}

// Close logs the closure of a UDP session.
func (l *udpEventLoggerImpl) Close(sessionID uint32, err error) {
	if l.EventLogger != nil {
		l.EventLogger.UDPError(l.Conn.RemoteAddr(), l.AuthID, sessionID, err)
	}
}
