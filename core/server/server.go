package server

import (
	"context"
	utls "github.com/refraction-networking/utls"
	"encoding/json"
	"io"
	"math/rand"
    "net"
	"net/http"
	"strings"
	"sync"
	"time"
	"fmt" // 导入 fmt 用于错误格式化

	"github.com/XLESSGo/uquic"
	"github.com/XLESSGo/uquic/http3"
	"github.com/FakeTCP/FakeTCP"

	"github.com/XLESSGo/XLESS/core/internal/congestion"
	protocol "github.com/XLESSGo/XLESS/core/internal/protocol" // 导入 core/internal/protocol 为 protocol
	protocol_ext "github.com/XLESSGo/XLESS/core/protocol"      // 导入 core/protocol 为 protocol_ext
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

type XListener interface {
	Accept(ctx context.Context) (net.Conn, error)
	Addr() net.Addr
	Close() error
}

type quicListenerWrapper struct {
	*quic.Listener
}

func (l *quicListenerWrapper) Accept(ctx context.Context) (net.Conn, error) {
	return l.Listener.Accept(ctx)
}

type serverImpl struct {
	config   *Config
	listener XListener
	protocol protocol_ext.Protocol
}

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

func (s *serverImpl) handleClient(conn net.Conn) {
	switch c := conn.(type) {
	case quic.Connection:
		s.handleQUICClient(c)
	case *faketcp.XStreamConn:
		adapter := newQuicAdapter(c)
		s.handleQUICClient(adapter)
	default:
		log.Printf("Received an unknown connection type from %s", conn.RemoteAddr())
		conn.Close()
	}
}

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

// quicAdapter实现了quic.Connection接口，将FakeTCP流适配为QUIC数据报。
type quicAdapter struct {
	*faketcp.XStreamConn
}

func newQuicAdapter(conn *faketcp.XStreamConn) *quicAdapter {
	return &quicAdapter{XStreamConn: conn}
}

// ReceiveDatagram 负责从 FakeTCP 流中读取并还原 UDP 数据报。
func (a *quicAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	// 实现从 FakeTCP 流中读取和还原 UDP 数据报的逻辑。
	msg, err := a.XStreamConn.ReadUDPFromStream()
	if err != nil {
		return nil, err
	}
	return msg.Payload, nil
}

// SendDatagramWithAddr 是一个自定义方法，用于在知道地址的情况下发送数据报。
func (a *quicAdapter) SendDatagramWithAddr(payload []byte, addr net.Addr) error {
	return a.XStreamConn.WriteUDPToStream(&faketcp.XUDPMessage{
		Addr:    addr,
		Payload: payload,
	})
}

// SendDatagram 负责将 UDP 数据报封装并写入 FakeTCP 流。
// 由于 SendDatagramWithAddr 已经处理了发送逻辑，这个方法可以保持简洁。
func (a *quicAdapter) SendDatagram(b []byte) error {
	// 在 FakeTCP 适配器中，通常不直接调用此方法，因为没有地址信息。
	// 上层逻辑会调用 SendDatagramWithAddr。
	return fmt.Errorf("address required for FakeTCP datagram, use SendDatagramWithAddr")
}

type h3sHandler struct {
	config        *Config
	conn          quic.Connection
	authenticated bool
	authMutex     sync.Mutex
	authID        string
	connID        uint32 // 用于转储流的随机 ID
	udpSM         *udpSessionManager
	decoyProxy    *DecoyProxy
	protocol      protocol_ext.Protocol // h3sHandler 也需要协议插件
}

func newH3sHandler(config *Config, conn quic.Connection) *h3sHandler {
	return &h3sHandler{
		config:     config,
		conn:       conn,
		connID:     rand.Uint32(),
		decoyProxy: NewDecoyProxy(config.DecoyURL), // Config 必须有 DecoyURL 字段
	}
}

// isObfuscatedAuthRequest 根据 XLESS 规范确定请求是否是混淆的认证请求。
func isObfuscatedAuthRequest(r *http.Request) bool {
	// 1. 路径必须在 API 路径池中
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
	// 2. 必须有 Authorization 或 Cookie 头，且带有可信的令牌
	authH := r.Header.Get("Authorization")
	cookieH := r.Header.Get("Cookie")
	if !strings.Contains(authH, "Bearer ") && !strings.Contains(cookieH, "session_id=") {
		return false
	}
	// 3. Content-Type 必须是 application/json 或 application/x-www-form-urlencoded
	ctype := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ctype, "application/json") &&
		!strings.HasPrefix(ctype, "application/x-www-form-urlencoded") {
		return false
	}
	// 4. JSON Body 中必须有 token 字段
	if !strings.HasPrefix(ctype, "application/json") {
		return true // 对于 urlencoded 跳过深度检查
	}
	bodyRaw, err := io.ReadAll(r.Body)
	if err != nil || len(bodyRaw) == 0 {
		return false
	}
	var body map[string]interface{}
	_ = json.Unmarshal(bodyRaw, &body)
	// 恢复 Body 以供其他处理程序读取
	r.Body = io.NopCloser(strings.NewReader(string(bodyRaw)))
	_, hasToken := body["token"]
	return hasToken
}

func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 锁定以进行线程安全的认证状态更新。
	h.authMutex.Lock()
	defer h.authMutex.Unlock()

	// 如果尚未认证，检查混淆的认证请求。
	if !h.authenticated && isObfuscatedAuthRequest(r) {
		// 从混淆请求中解析认证信息。
		authReq := protocol.AuthRequestFromObfuscated(r) // 使用 protocol (internal)
		actualTx := authReq.Rx
		ok, id := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), authReq.Auth, actualTx)
		if ok {
			// 认证成功，设置状态并应用拥塞控制策略。
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
			// 发送认证响应头。
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{ // 使用 protocol (internal)
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK) // 使用 protocol (internal)
			// 记录日志。
			if tl := h.config.TrafficLogger; tl != nil {
				tl.LogOnlineState(id, true)
			}
			if el := h.config.EventLogger; el != nil {
				el.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			// 如果 UDP 启用，初始化 UDP 会话管理器。
			if !h.config.DisableUDP {
				go func() {
					sm := newUDPSessionManager(
						&udpIOImpl{h.conn, id, h.config.TrafficLogger, h.config.RequestHook, h.config.Outbound, h.protocol}, // 传递 h.protocol
						&udpEventLoggerImpl{h.conn, id, h.config.EventLogger},
						h.config.UDPIdleTimeout)
					h.udpSM = sm
					go sm.Run()
				}()
			}
			return
		} else {
			// 认证失败：透明转发到诱饵。
			h.decoyProxy.ServeHTTP(w, r)
			return
		}
	}

	// 如果未认证，透明转发到诱饵服务。
	if !h.authenticated {
		h.decoyProxy.ServeHTTP(w, r)
		return
	}

	// 已经认证：响应任何进一步的认证请求。
	if isObfuscatedAuthRequest(r) {
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{ // 使用 protocol (internal)
			UDPEnabled: !h.config.DisableUDP,
			Rx:         h.config.BandwidthConfig.MaxRx,
			RxAuto:     h.config.IgnoreClientBandwidth,
		})
		w.WriteHeader(protocol.StatusAuthOK) // 使用 protocol (internal)
		return
	}

	// 认证后，所有非认证 HTTP 请求由 masqHandler 处理。
	h.masqHandler(w, r) // 保留 MasqHandler
}

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, id quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
	if err != nil || !h.authenticated {
		return false, nil
	}

	// 使用 QStream 包装流，QStream 处理 Close()
	stream = &utils.QStream{Stream: stream}

	switch ft {
	case protocol.FrameTypeTCPRequest: // 使用 protocol (internal)
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

	// 读取请求
	reqAddr, err := protocol.ReadTCPRequest(stream) // 使用 protocol (internal)
	if err != nil {
		_ = stream.Close()
		return
	}
	
	// 在解密后第一时间还原协议字段 (服务器端)
	if h.protocol != nil {
		ctx := protocol_ext.ProtocolContext{ // 使用 protocol_ext
			Type:     "tcp_request",
			IsClient: false, // 服务器端
			PeerAddr: h.conn.RemoteAddr(),
			StreamID: stream.StreamID(),
		}
		modifiedReqAddrData, pErr := h.protocol.Deobfuscate(reqAddr, ctx)
		if pErr != nil {
			_ = protocol.WriteTCPResponse(stream, false, fmt.Sprintf("protocol deobfuscation failed: %s", pErr.Error())) // 使用 protocol (internal)
			_ = stream.Close()
			return
		}
		reqAddr = modifiedReqAddrData.(string) // 类型断言回 string
	}
	
	streamStats.ReqAddr.Store(reqAddr)
	// 如果设置了 Hook，则调用 Hook
	var putback []byte
	var hooked bool
	if h.config.RequestHook != nil {
		hooked = h.config.RequestHook.Check(false, reqAddr)
		// 当 Hook 启用时，服务器应始终接受连接，以便客户端发送 Hook 想要看到的任何请求。
		// 这本质上是服务器端的快速打开。
		if hooked {
			streamStats.State.Store(StreamStateHooking)
			_ = protocol.WriteTCPResponse(stream, true, "RequestHook enabled") // 使用 protocol (internal)
			putback, err = h.config.RequestHook.TCP(stream, &reqAddr)
			if err != nil {
				_ = stream.Close()
				return
			}
			streamStats.setHookedReqAddr(reqAddr)
		}
	}
	// 记录事件
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), h.authID, reqAddr)
	}
	// 拨号目标
	streamStats.State.Store(StreamStateConnecting)
	tConn, err := h.config.Outbound.TCP(reqAddr)
	if err != nil {
		if !hooked {
			_ = protocol.WriteTCPResponse(stream, false, err.Error()) // 使用 protocol (internal)
		}
		_ = stream.Close()
		// 记录错误
		if h.config.EventLogger != nil {
			h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
		}
		return
	}
	if !hooked {
		_ = protocol.WriteTCPResponse(stream, true, "Connected") // 使用 protocol (internal)
	}
	streamStats.State.Store(StreamStateEstablished)
	// 如果 Hook 请求，则放回数据
	if len(putback) > 0 {
		n, _ := tConn.Write(putback)
		streamStats.Tx.Add(uint64(n))
	}
	// 开始代理
	if trafficLogger != nil {
		err = copyTwoWayEx(h.authID, stream, tConn, trafficLogger, streamStats)
	} else {
		// 如果未设置流量记录器，则使用快速路径
		err = copyTwoWay(stream, tConn)
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
	}
	// 清理
	_ = tConn.Close()
	_ = stream.Close()
	// 如果 TrafficLogger 请求断开客户端
	if err == errDisconnect {
		_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
	}
}

func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		// 对所有请求返回 404
		http.NotFound(w, r)
	}
}

// udpIOImpl 是带有 TrafficLogger 支持的 udpSessionManager 的 IO 实现
type udpIOImpl struct {
	Conn          quic.Connection
	AuthID        string
	TrafficLogger TrafficLogger
	RequestHook   RequestHook
	Outbound      Outbound
	Protocol      protocol_ext.Protocol // 传递协议插件给 udpIOImpl
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) { // 使用 protocol (internal)
	for {
		msgRaw, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// 连接错误，这将停止会话管理器
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msgRaw) // 解析原始 UDP 消息，使用 protocol (internal)
		if err != nil {
			// 无效消息，这没关系 - 只需等待下一个
			continue
		}

		// 在解密后第一时间还原协议字段 (服务器端接收 UDP)
		if io.Protocol != nil {
			ctx := protocol_ext.ProtocolContext{ // 使用 protocol_ext
				Type:     "udp_message",
				IsClient: false, // 服务器端
				PeerAddr: io.Conn.RemoteAddr(),
				SessionID: udpMsg.SessionID,
			}
			modifiedUDPMsgData, pErr := io.Protocol.Deobfuscate(udpMsg, ctx)
			if pErr != nil {
				// 协议解密失败，丢弃此包
				continue
			}
			udpMsg = modifiedUDPMsgData.(*protocol.UDPMessage) // 类型断言回 *protocol.UDPMessage (internal)
		}

		if io.TrafficLogger != nil {
			ok := io.TrafficLogger.LogTraffic(io.AuthID, uint64(len(udpMsg.Data)), 0)
			if !ok {
				// TrafficLogger 请求断开客户端
				_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
				return nil, errDisconnect
			}
		}
		return udpMsg, nil
	}
}

// SendMessage 负责将 UDP 消息封装并发送。
// 它现在会根据连接类型，选择性地调用 SendDatagram 或 SendDatagramWithAddr。
func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	if io.TrafficLogger != nil {
		ok := io.TrafficLogger.LogTraffic(io.AuthID, 0, uint64(len(msg.Data)))
		if !ok {
			_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return errDisconnect
		}
	}
	
	// 在加密封装前最后一刻修改协议字段 (服务器端发送 UDP)
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

	// 使用类型断言来处理 FakeTCP 适配器
	if adapter, ok := io.Conn.(*quicAdapter); ok {
		// 如果是 FakeTCP 连接，我们调用新的 SendDatagramWithAddr 方法
		return adapter.SendDatagramWithAddr(finalMsg.Data, msg.Addr)
	} else {
		// 否则，使用标准的 QUIC 连接方法
		msgN := finalMsg.Serialize(buf)
		if msgN < 0 {
			return nil
		}
		return io.Conn.SendDatagram(buf[:msgN])
	}
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
