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
	closeErrCodeOK            = 0x100
	closeErrCodeProtocolError = 0x101
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
	Tx         uint64
}

// clientImpl 是 Client 接口的具体实现。
type clientImpl struct {
	config *Config
	pktConn net.PacketConn
	conn    quic.Connection
	udpSM *udpSessionManager
	protocol protocol_ext.Protocol
}

// NewClient 创建并返回一个新的 Client 实例。
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

// connect 负责建立与服务器的连接和握手。
func (c *clientImpl) connect() (*HandshakeInfo, error) {
	var conn quic.Connection
	var rt http.RoundTripper

	// 如果使用 FakeTCP，则使用自定义的连接和 RoundTripper
	if c.config.XLESSUseFakeTCP {
		log.Println("Using FakeTCP for connection")
		tcpConn, err := faketcp.Dial(c.config.ServerAddr.String())
		if err != nil {
			return nil, coreErrs.ConnectError{Err: err}
		}
		// 将 FakeTCP 连接包装为 quicAdapter
		conn = newQuicAdapter(tcpConn)
		c.conn = conn
		
		// FakeTCP 模式下，需要使用自定义的 http3.RoundTripper 适配 FakeTCP 连接
		rt = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				return conn.(quic.EarlyConnection), nil
			},
			TLSClientConfig: &utls.Config{InsecureSkipVerify: true},
		}

	} else {
		// 否则，使用标准的 QUIC 连接
		pktConn, err := c.config.ConnFactory.New(c.config.ServerAddr)
		if err != nil {
			return nil, err
		}
		c.pktConn = pktConn

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

		if c.config.EnableUQUIC {
			quicSpec, err := quic.QUICID2Spec(c.config.UQUICSpecID)
			if err != nil {
				_ = pktConn.Close()
				return nil, coreErrs.ConnectError{Err: err}
			}
			rt = &http3.RoundTripper{
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
		} else {
			rt = &http3.RoundTripper{
				TLSClientConfig: tlsConfig,
				QUICConfig:      quicConfig,
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

	// 执行混淆的网页浏览行为
	decoyURL := c.config.DecoyURL
	httpClient := &http.Client{Timeout: 4 * time.Second}
	resources, _ := SimulateWebBrowse(httpClient, decoyURL)
	sendAuxiliaryRequests(httpClient, resources)

	// 统一的认证请求发送逻辑
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
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		if c.pktConn != nil {
			_ = c.pktConn.Close()
		}
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}

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
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn, Protocol: c.protocol})
	}
	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

func (c *clientImpl) openStream() (quic.Stream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string) (net.Conn, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}

	var finalAddr string = addr
	if c.protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:     "tcp_request",
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

	err = protocol.WriteTCPRequest(stream, finalAddr)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if c.config.FastOpen {
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
			Established:      false,
			protocol:         c.protocol,
			isClient:         true,
			peerAddr:         c.conn.RemoteAddr(),
			streamID:         stream.StreamID(),
		}, nil
	}
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}

	if c.protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:     "tcp_response",
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
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		Established:      true,
		protocol:         c.protocol,
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
	_ = c.conn.CloseWithError(closeErrCodeOK, "")
	if c.pktConn != nil {
		_ = c.pktConn.Close()
	}
	return nil
}

var nonPermanentErrors = []error{
	quic.StreamLimitReachedError{},
}

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
	protocol         protocol_ext.Protocol
	isClient         bool
	peerAddr         net.Addr
	streamID         quic.StreamID
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if c.protocol != nil {
			ctx := protocol_ext.ProtocolContext{
				Type:     "tcp_response",
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
	Protocol protocol_ext.Protocol
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		// 使用类型断言来处理 FakeTCP 适配器
		if adapter, ok := io.Conn.(*quicAdapter); ok {
			msg, err := adapter.ReadUDPFromStream()
			if err != nil {
				return nil, err
			}
			return &protocol.UDPMessage{
				SessionID: 0,
				Addr:      msg.Addr.String(),
				Data:      msg.Payload,
			}, nil
		}
		
		msgRaw, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msgRaw)
		if err != nil {
			continue
		}
		
		if io.Protocol != nil {
			ctx := protocol_ext.ProtocolContext{
				Type:     "udp_message",
				IsClient: true,
				PeerAddr: io.Conn.RemoteAddr(),
				SessionID: udpMsg.SessionID,
			}
			modifiedUDPMsgData, pErr := io.Protocol.Deobfuscate(udpMsg, ctx)
			if pErr != nil {
				continue
			}
			udpMsg = modifiedUDPMsgData.(*protocol.UDPMessage)
		}

		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	var finalMsg *protocol.UDPMessage = msg
	if io.Protocol != nil {
		ctx := protocol_ext.ProtocolContext{
			Type:      "udp_message",
			IsClient:  true,
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

// --- 以下为适配 FakeTCP 的新类型和方法 ---

// quicAdapter 包装了一个 FakeTCP 连接以实现 quic.Connection 接口。
type quicAdapter struct {
	conn net.Conn
	mu   sync.Mutex
}

// newQuicAdapter 创建一个新的 quicAdapter。
func newQuicAdapter(conn net.Conn) *quicAdapter {
	return &quicAdapter{conn: conn}
}

// ReadUDPFromStream 从 FakeTCP 流中读取一个完整的 UDP 消息。
func (a *quicAdapter) ReadUDPFromStream() (*faketcp.XUDPMessage, error) {
	// 读取地址长度 (4 bytes)
	var addrLen uint32
	err := binary.Read(a.conn, binary.BigEndian, &addrLen)
	if err != nil {
		return nil, err
	}
	
	// 读取地址
	addrBytes := make([]byte, addrLen)
	_, err = io.ReadFull(a.conn, addrBytes)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", string(addrBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}
	
	// 读取 payload 长度 (4 bytes)
	var payloadLen uint32
	err = binary.Read(a.conn, binary.BigEndian, &payloadLen)
	if err != nil {
		return nil, err
	}
	
	// 读取 payload
	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(a.conn, payload)
	if err != nil {
		return nil, err
	}
	
	return &faketcp.XUDPMessage{Addr: addr, Payload: payload}, nil
}

// WriteUDPToStream 将 UDP 消息封装并通过 FakeTCP 连接发送。
func (a *quicAdapter) WriteUDPToStream(msg *faketcp.XUDPMessage) error {
	addrBytes := []byte(msg.Addr.String())
	payloadBytes := msg.Payload
	
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, uint32(len(addrBytes)))
	buffer.Write(addrBytes)
	binary.Write(&buffer, binary.BigEndian, uint32(len(payloadBytes)))
	buffer.Write(payloadBytes)
	
	_, err := a.conn.Write(buffer.Bytes())
	return err
}

// SendDatagramWithAddr 是一个自定义方法，用于在知道地址的情况下发送数据报。
func (a *quicAdapter) SendDatagramWithAddr(payload []byte, addr net.Addr) error {
	return a.WriteUDPToStream(&faketcp.XUDPMessage{
		Addr:    addr,
		Payload: payload,
	})
}

// ReceiveDatagram 负责从 FakeTCP 流中读取并还原 UDP 数据报。
func (a *quicAdapter) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	msg, err := a.ReadUDPFromStream()
	if err != nil {
		return nil, err
	}
	return msg.Payload, nil
}

// SendDatagram 负责将 UDP 数据报封装并写入 FakeTCP 流。
func (a *quicAdapter) SendDatagram(b []byte) error {
	return fmt.Errorf("address required for FakeTCP datagram, use SendDatagramWithAddr")
}

// 以下是 quic.Connection 接口中其他方法的实现，为了满足接口要求。
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

func (a *quicAdapter) HandshakeComplete() context.Context {
	return context.Background()
}

func (a *quicAdapter) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

func (a *quicAdapter) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	return a.conn.Close()
}

func (a *quicAdapter) Context() context.Context {
	return context.Background()
}

func (a *quicAdapter) RemoteAddr() net.Addr {
	return a.conn.RemoteAddr()
}

func (a *quicAdapter) LocalAddr() net.Addr {
	return a.conn.LocalAddr()
}

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

// CloseWithError 和 Close 是一个 FakeTCP 连接，因此我们直接使用 Close。
func (a *quicAdapter) Close() error {
	return a.conn.Close()
}
