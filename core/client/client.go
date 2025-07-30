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
	"fmt" // 导入 fmt

	coreErrs "github.com/XLESSGo/XLESS/core/errors"
	"github.com/XLESSGo/XLESS/core/internal/congestion"
	protocol "github.com/XLESSGo/XLESS/core/internal/protocol" // 导入 core/internal/protocol 为 protocol
	protocol_ext "github.com/XLESSGo/XLESS/core/protocol"      // 导入 core/protocol 为 protocol_ext
	"github.com/XLESSGo/XLESS/core/internal/utils"

	"github.com/XLESSGo/uquic"
	"github.com/XLESSGo/uquic/http3"
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
	
	// 实例化 Protocol 插件
	var p protocol_ext.Protocol
	if config.Protocol != "" && config.Protocol != "plain" && config.Protocol != "origin" {
		var err error
		p, err = protocol_ext.NewProtocol(config.Protocol, config.ProtocolParam)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load protocol plugin %q: %w", config.Protocol, err)
		}
	}
	
	c := &clientImpl{
		config: config,
		protocol: p, // 传递 protocol 插件
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
	protocol protocol_ext.Protocol // 存储协议插件实例
}

func (c *clientImpl) connect() (*HandshakeInfo, error) {
	pktConn, err := c.config.ConnFactory.New(c.config.ServerAddr)
	if err != nil {
		return nil, err
	}

	tlsConfig := &utls.Config{
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
		quicSpec, err := quic.QUICID2Spec(c.config.UQUICSpecID)
		if err != nil {
			_ = pktConn.Close()
			return nil, coreErrs.ConnectError{Err: err}
		}

		uquicRT := &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
			QUICConfig:      quicConfig,
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
		rt = uquicRT
	} else {
		rt = &http3.RoundTripper{
			TLSClientConfig: tlsConfig,
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, _ string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				// quic.DialEarly directly accepts net.Addr for remoteAddr.
				qc, err := quic.DialEarly(ctx, pktConn, c.config.ServerAddr, tlsCfg, cfg)
				if err != nil {
					return nil, err
				}
				conn = qc
				return qc, nil
			},
		}
	}

	decoyURL := c.config.DecoyURL
	httpClient := &http.Client{Timeout: 4 * time.Second}
	resources, _ := SimulateWebBrowse(httpClient, decoyURL)
	sendAuxiliaryRequests(httpClient, resources)

	apiPath, query := randomAPIPathAndQuery()
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme:   "https",
			Host:     protocol.URLHost, // 使用 protocol (internal)
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

	time.Sleep(time.Duration(500+rand.Intn(1200)) * time.Millisecond)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "") // 保持原始错误码
		}
		_ = pktConn.Close()
		return nil, coreErrs.ConnectError{Err: err}
	}

	if resp.StatusCode != protocol.StatusAuthOK { // 使用 protocol (internal)
		_ = conn.CloseWithError(closeErrCodeProtocolError, "") // 保持原始错误码
		_ = pktConn.Close()
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}

	authResp := protocol.AuthResponseFromHeader(resp.Header) // 使用 protocol (internal)
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
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn, Protocol: c.protocol}) // 传递 c.protocol
	}

	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

// openStream 使用 QStream 包装流，QStream 处理 Close()
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
	
	// 在加密封装前最后一刻修改协议字段 (客户端)
	var finalAddr string = addr
	if c.protocol != nil {
		ctx := protocol_ext.ProtocolContext{ // 使用 protocol_ext
			Type:     "tcp_request",
			IsClient: true, // 客户端
			PeerAddr: c.conn.RemoteAddr(),
			StreamID: stream.StreamID(),
		}
		modifiedAddrData, pErr := c.protocol.Obfuscate(addr, ctx)
		if pErr != nil {
			_ = stream.Close()
			return nil, fmt.Errorf("protocol obfuscation failed: %w", pErr)
		}
		finalAddr = modifiedAddrData.(string) // 类型断言回 string
	}
	
	// 发送请求
	err = protocol.WriteTCPRequest(stream, finalAddr) // 使用 protocol (internal)，并使用可能修改过的 finalAddr
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if c.config.FastOpen {
		// 当快速打开启用时，不等待响应。
		// 立即返回连接，将响应处理推迟到第一次 Read() 调用。
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
			Established:      false,
			protocol:         c.protocol, // 传递 protocol 给 tcpConn
			isClient:         true,
			peerAddr:         c.conn.RemoteAddr(),
			streamID:         stream.StreamID(),
		}, nil
	}
	// 读取响应
	ok, msg, err := protocol.ReadTCPResponse(stream) // 读取原始响应，使用 protocol (internal)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}

	// 在解密后第一时间还原协议字段 (客户端，如果插件修改了响应)
	// 目前协议插件只处理 reqAddr，但为了未来扩展性，可以保留这个逻辑
	if c.protocol != nil {
		ctx := protocol_ext.ProtocolContext{ // 使用 protocol_ext
			Type:     "tcp_response", // 假设协议插件可能处理响应
			IsClient: true,
			PeerAddr: c.conn.RemoteAddr(),
			StreamID: stream.StreamID(),
		}
		// 这里需要根据协议插件如何修改响应来决定如何处理 ok 和 msg
		// _, _ = c.protocol.Deobfuscate(msg, ctx) // 示例：如果 msg 是 ProtocolData
		_, _ = ctx, ok // 避免 unused 警告
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
		protocol:         c.protocol, // 传递 protocol 给 tcpConn
		isClient:         true,
		peerAddr:         c.conn.RemoteAddr(),
		streamID:         stream.StreamID(),
	}, nil
}

func (c *clientImpl) UDP() (HyUDPConn, error) {
	if c.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	return c.udpSM.NewUDP()
}

func (c *clientImpl) Close() error {
	_ = c.conn.CloseWithError(closeErrCodeOK, "") // 保持原始错误码
	_ = c.pktConn.Close()
	return nil
}

var nonPermanentErrors = []error{
	quic.StreamLimitReachedError{},
}

// wrapIfConnectionClosed 检查 quic-go 返回的错误是否可恢复 (列在 nonPermanentErrors 中) 或永久性。
// 可恢复的错误按原样返回，永久性的错误包装为 ClosedError。
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
	protocol         protocol_ext.Protocol // tcpConn 也需要协议插件
	isClient         bool
	peerAddr         net.Addr
	streamID         quic.StreamID
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// 读取响应
		ok, msg, err := protocol.ReadTCPResponse(c.Orig) // 使用 protocol (internal)
		if err != nil {
			return 0, err
		}
		
		// 在解密后第一时间还原协议字段 (客户端，如果插件修改了响应)
		// 再次提醒：SimpleAddrOffset 示例插件不影响响应，但为通用性保留此结构
		if c.protocol != nil {
			ctx := protocol_ext.ProtocolContext{ // 使用 protocol_ext
				Type:     "tcp_response",
				IsClient: c.isClient,
				PeerAddr: c.peerAddr,
				StreamID: c.streamID,
			}
			// 这里假设 msg 是可以被修改的，如果 ok 状态也可能被修改，则需要更复杂的逻辑
			// _, _ = c.protocol.Deobfuscate(msg, ctx) // 示例：如果 msg 是 ProtocolData
			_, _ = ctx, ok // 避免 unused 警告
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
	Protocol protocol_ext.Protocol // udpIOImpl 也需要协议插件
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

		// 在解密后第一时间还原协议字段 (客户端接收 UDP)
		if io.Protocol != nil {
			ctx := protocol_ext.ProtocolContext{ // 使用 protocol_ext
				Type:     "udp_message",
				IsClient: true, // 客户端
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

		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error { // 使用 protocol (internal)
	// 在加密封装前最后一刻修改协议字段 (客户端发送 UDP)
	var finalMsg *protocol.UDPMessage = msg // 使用 protocol (internal)
	if io.Protocol != nil {
		ctx := protocol_ext.ProtocolContext{ // 使用 protocol_ext
			Type:     "udp_message",
			IsClient: true, // 客户端
			PeerAddr: io.Conn.RemoteAddr(),
			SessionID: msg.SessionID,
		}
		modifiedUDPMsgData, pErr := io.Protocol.Obfuscate(msg, ctx)
		if pErr != nil {
			return fmt.Errorf("protocol obfuscation failed: %w", pErr)
		}
		finalMsg = modifiedUDPMsgData.(*protocol.UDPMessage) // 类型断言回 *protocol.UDPMessage (internal)
	}

	msgN := finalMsg.Serialize(buf) // 使用可能修改过的 finalMsg
	if msgN < 0 {
		// 消息大于缓冲区，静默丢弃
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}
