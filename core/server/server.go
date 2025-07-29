package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/XLESSGo/uquic"
	"github.com/XLESSGo/uquic/http3"
	utls "github.com/refraction-networking/utls" // Add this import with alias

	"github.com/XLESSGo/XLESS/core/internal/congestion"
	"github.com/XLESSGo/XLESS/core/internal/protocol"
	"github.com/XLESSGo/XLESS/core/internal/utils"
)

// --- Dynamic API path pool, must be same as client ---
var commonAPIPaths = []string{
	"/api/v1/auth", "/user/login", "/oauth/token", "/session/create",
	"/api/session", "/auth/v2/login", "/web/auth/verify",
	"/api/user/validate", "/signin", "/accounts/session", "/v2/access", "/api/v3/authenticate",
}

const (
	closeErrCodeOK                  = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeTrafficLimitReached = 0x107 // HTTP3 ErrCodeExcessiveLoad
)

type Server interface {
	Serve() error
	Close() error
}

package server

import (
	"context"
	"crypto/tls" // Standard TLS library
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/XLESSGo/uquic"
	"github.com/XLESSGo/uquic/http3"
	utls "github.com/refraction-networking/utls" // utls library, aliased for clarity

	"github.com/XLESSGo/XLESS/core/internal/congestion"
	"github.com/XLESSGo/XLESS/core/internal/protocol"
	"github.com/XLESSGo/XLESS/core/internal/utils"
)

// ... (previous code remains the same until NewServer)

func NewServer(config *Config) (Server, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}

	// Create a *utls.Config instance to be used by uquic/http3
	utlsConfig := &utls.Config{}

	// --- Fix 1 & 4: Convert []crypto/tls.Certificate to []utls.Certificate ---
	// Error: server/server.go:56:50: cannot convert cert (variable of struct type "crypto/tls".Certificate) to type "github.com/refraction-networking/utls".Certificate
	// This means config.TLSConfig.Certificates contains crypto/tls.Certificate.
	// We need to convert each element to utls.Certificate.
	if len(config.TLSConfig.Certificates) > 0 {
		utlsConfig.Certificates = make([]utls.Certificate, len(config.TLSConfig.Certificates))
		for i, cert := range config.TLSConfig.Certificates {
			utlsConfig.Certificates[i] = utls.Certificate(cert) // Direct struct-to-struct conversion
		}
	}

	// --- Fix 2 & 3: Wrap GetCertificate function for type compatibility ---
	// Error: server/server.go:67:24: cannot use info.SupportedCurves (variable of type []"github.com/refraction-networking/utls".CurveID) as []"crypto/tls".CurveID value in struct literal
	// Error: server/server.go:69:24: cannot use info.SignatureSchemes (variable of type []"github.com/refraction-networking/utls".SignatureScheme) as []"crypto/tls".SignatureScheme value in struct literal
	// Error: server/server.go:78:33: cannot convert *stdCert (variable of struct type "crypto/tls".Certificate) to type "github.com/refraction-networking/utls".Certificate

	// This wrapper function will translate between utls.ClientHelloInfo
	// and crypto/tls.ClientHelloInfo, and between crypto/tls.Certificate
	// and utls.Certificate.
	if config.TLSConfig.GetCertificate != nil {
		utlsConfig.GetCertificate = func(info *utls.ClientHelloInfo) (*utls.Certificate, error) {
			// Convert utls.ClientHelloInfo to crypto/tls.ClientHelloInfo
			// Note: SupportedPoints in utls is []uint8, crypto/tls is []tls.CurveP256.
			// Direct conversion `[]tls.CurveP256(info.SupportedPoints)` might not be robust
			// if the underlying type is not a simple alias. Let's try direct casting first.
			// If it fails, we might need a manual loop or check the actual underlying types.
			stdInfo := &tls.ClientHelloInfo{ // Using standard crypto/tls types here
				CipherSuites:      info.CipherSuites,
				ServerName:        info.ServerName,
				SupportedCurves:   []tls.CurveID(info.SupportedCurves),   // Convert []utls.CurveID to []crypto/tls.CurveID
				SupportedPoints:   []tls.CurveP256(info.SupportedPoints), // Convert []utls.CurveP256 to []crypto/tls.CurveP256
				SignatureSchemes:  []tls.SignatureScheme(info.SignatureSchemes), // Convert []utls.SignatureScheme to []crypto/tls.SignatureScheme
				SupportedVersions: info.SupportedVersions,
				Conn:              info.Conn,
			}

			// Call the original GetCertificate function from config.TLSConfig
			// This function is expected to return *crypto/tls.Certificate
			stdCert, err := config.TLSConfig.GetCertificate(stdInfo)
			if err != nil {
				return nil, err
			}
			if stdCert == nil {
				return nil, nil // Important: return nil, nil if no certificate is found
			}

			// Convert the returned *crypto/tls.Certificate to *utls.Certificate
			utlsCert := utls.Certificate(*stdCert) // Convert struct, then take address
			return &utlsCert, nil
		}
	}

	// Now, utlsConfig is correctly populated with utls types,
	// so it can be passed to http3.ConfigureTLSConfig
	tlsConfig := http3.ConfigureTLSConfig(utlsConfig)

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
	listener, err := quic.Listen(config.Conn, tlsConfig, quicConfig)
	if err != nil {
		_ = config.Conn.Close()
		return nil, err
	}
	return &serverImpl{
		config:   config,
		listener: listener,
	}, nil
}

type serverImpl struct {
	config   *Config
	listener *quic.Listener
}

func (s *serverImpl) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

func (s *serverImpl) Close() error {
	err := s.listener.Close()
	_ = s.config.Conn.Close()
	return err
}

func (s *serverImpl) handleClient(conn quic.Connection) {
	handler := newH3sHandler(s.config, conn)
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

type h3sHandler struct {
	config        *Config
	conn          quic.Connection
	authenticated bool
	authMutex     sync.Mutex
	authID        string
	connID        uint32 // a random id for dump streams
	udpSM         *udpSessionManager
	decoyProxy    *DecoyProxy
}

func newH3sHandler(config *Config, conn quic.Connection) *h3sHandler {
	return &h3sHandler{
		config:     config,
		conn:       conn,
		connID:     rand.Uint32(),
		decoyProxy: NewDecoyProxy(config.DecoyURL), // Config must have DecoyURL field
	}
}

// Determines if a request is an obfuscated authentication request according to XLESS SPEC.
func isObfuscatedAuthRequest(r *http.Request) bool {
	// 1. Path must be in API path pool
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
	// 2. Must have Authorization or Cookie header with a plausible token
	authH := r.Header.Get("Authorization")
	cookieH := r.Header.Get("Cookie")
	if !strings.Contains(authH, "Bearer ") && !strings.Contains(cookieH, "session_id=") {
		return false
	}
	// 3. Must have Content-Type = application/json or application/x-www-form-urlencoded
	ctype := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ctype, "application/json") &&
		!strings.HasPrefix(ctype, "application/x-www-form-urlencoded") {
		return false
	}
	// 4. Must have a token field in JSON body
	if !strings.HasPrefix(ctype, "application/json") {
		return true // skip deep check for urlencoded
	}
	bodyRaw, err := io.ReadAll(r.Body)
	if err != nil || len(bodyRaw) == 0 {
		return false
	}
	var body map[string]interface{}
	_ = json.Unmarshal(bodyRaw, &body)
	// Restore the body for further reading (needed by other handlers)
	r.Body = io.NopCloser(strings.NewReader(string(bodyRaw)))
	_, hasToken := body["token"]
	return hasToken
}

func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Lock for thread-safe authentication state update.
	h.authMutex.Lock()
	defer h.authMutex.Unlock()

	// If not yet authenticated, check for obfuscated authentication request.
	if !h.authenticated && isObfuscatedAuthRequest(r) {
		// Parse authentication information from obfuscated request.
		authReq := protocol.AuthRequestFromObfuscated(r)
		actualTx := authReq.Rx
		ok, id := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), authReq.Auth, actualTx)
		if ok {
			// Authentication successful, set state and apply congestion policy.
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
			// Send authentication response headers.
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			// Logging.
			if tl := h.config.TrafficLogger; tl != nil {
				tl.LogOnlineState(id, true)
			}
			if el := h.config.EventLogger; el != nil {
				el.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			// Initialize UDP session manager if UDP is enabled.
			if !h.config.DisableUDP {
				go func() {
					sm := newUDPSessionManager(
						&udpIOImpl{h.conn, id, h.config.TrafficLogger, h.config.RequestHook, h.config.Outbound},
						&udpEventLoggerImpl{h.conn, id, h.config.EventLogger},
						h.config.UDPIdleTimeout)
					h.udpSM = sm
					go sm.Run()
				}()
			}
			return
		} else {
			// Authentication failed: transparently forward to decoy.
			h.decoyProxy.ServeHTTP(w, r)
			return
		}
	}

	// If not authenticated, transparently forward to decoy service.
	if !h.authenticated {
		h.decoyProxy.ServeHTTP(w, r)
		return
	}

	// Already authenticated: respond to any further authentication request.
	if isObfuscatedAuthRequest(r) {
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !h.config.DisableUDP,
			Rx:         h.config.BandwidthConfig.MaxRx,
			RxAuto:     h.config.IgnoreClientBandwidth,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		return
	}

	// After authentication, all non-auth HTTP requests handled as proxy (fallback handler).
	h.masqHandler(w, r)
}

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, id quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
	if err != nil || !h.authenticated {
		return false, nil
	}

	// Wraps the stream with QStream, which handles Close() properly
	stream = &utils.QStream{Stream: stream}

	switch ft {
	case protocol.FrameTypeTCPRequest:
		go h.handleTCPRequest(stream)
		return true, nil
	default:
		return false, nil
	}
}

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

	// Read request
	reqAddr, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	streamStats.ReqAddr.Store(reqAddr)
	// Call the hook if set
	var putback []byte
	var hooked bool
	if h.config.RequestHook != nil {
		hooked = h.config.RequestHook.Check(false, reqAddr)
		// When the hook is enabled, the server should always accept a connection
		// so that the client will send whatever request the hook wants to see.
		// This is essentially a server-side fast-open.
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
	// Log the event
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), h.authID, reqAddr)
	}
	// Dial target
	streamStats.State.Store(StreamStateConnecting)
	tConn, err := h.config.Outbound.TCP(reqAddr)
	if err != nil {
		if !hooked {
			_ = protocol.WriteTCPResponse(stream, false, err.Error())
		}
		_ = stream.Close()
		// Log the error
		if h.config.EventLogger != nil {
			h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
		}
		return
	}
	if !hooked {
		_ = protocol.WriteTCPResponse(stream, true, "Connected")
	}
	streamStats.State.Store(StreamStateEstablished)
	// Put back the data if the hook requested
	if len(putback) > 0 {
		n, _ := tConn.Write(putback)
		streamStats.Tx.Add(uint64(n))
	}
	// Start proxying
	if trafficLogger != nil {
		err = copyTwoWayEx(h.authID, stream, tConn, trafficLogger, streamStats)
	} else {
		// Use the fast path if no traffic logger is set
		err = copyTwoWay(stream, tConn)
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
	}
	// Cleanup
	_ = tConn.Close()
	_ = stream.Close()
	// Disconnect the client if TrafficLogger requested
	if err == errDisconnect {
		_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
	}
}

func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		// Return 404 for everything
		http.NotFound(w, r)
	}
}

// udpIOImpl is the IO implementation for udpSessionManager with TrafficLogger support
type udpIOImpl struct {
	Conn          quic.Connection
	AuthID        string
	TrafficLogger TrafficLogger
	RequestHook   RequestHook
	Outbound      Outbound
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
		if io.TrafficLogger != nil {
			ok := io.TrafficLogger.LogTraffic(io.AuthID, uint64(len(udpMsg.Data)), 0)
			if !ok {
				// TrafficLogger requested to disconnect the client
				_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
				return nil, errDisconnect
			}
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	if io.TrafficLogger != nil {
		ok := io.TrafficLogger.LogTraffic(io.AuthID, 0, uint64(len(msg.Data)))
		if !ok {
			// TrafficLogger requested to disconnect the client
			_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return errDisconnect
		}
	}
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}

func (io *udpIOImpl) Hook(data []byte, reqAddr *string) error {
	if io.RequestHook != nil && io.RequestHook.Check(true, *reqAddr) {
		return io.RequestHook.UDP(data, reqAddr)
	} else {
		return nil
	}
}

func (io *udpIOImpl) UDP(reqAddr string) (UDPConn, error) {
	return io.Outbound.UDP(reqAddr)
}

type udpEventLoggerImpl struct {
	Conn        quic.Connection
	AuthID      string
	EventLogger EventLogger
}

func (l *udpEventLoggerImpl) New(sessionID uint32, reqAddr string) {
	if l.EventLogger != nil {
		l.EventLogger.UDPRequest(l.Conn.RemoteAddr(), l.AuthID, sessionID, reqAddr)
	}
}

func (l *udpEventLoggerImpl) Close(sessionID uint32, err error) {
	if l.EventLogger != nil {
		l.EventLogger.UDPError(l.Conn.RemoteAddr(), l.AuthID, sessionID, err)
	}
}
