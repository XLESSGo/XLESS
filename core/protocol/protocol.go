// core/protocol/protocol.go
package protocol

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	uquic "github.com/XLESSGo/uquic" // 假设需要 QUIC 类型用于上下文
)

// ====================================================================
// 现有协议常量和结构体 (从 core/internal/protocol 移动过来)
// ====================================================================

const (
	FrameTypeTCPRequest = 0x401
)

const (
	StatusAuthOK = http.StatusOK // Assuming 200 OK for successful authentication
)

const URLHost = "example.com" // Used by client for building auth request URL

// ReadTCPRequest reads a TCPRequest message from a QUIC stream.
// [varint] 0x401 (TCPRequest ID)
// [varint] Address length
// [bytes] Address string (host:port)
// [varint] Padding length
// [bytes] Random padding
func ReadTCPRequest(stream uquic.Stream) (string, error) {
	br := bufio.NewReader(stream)
	frameType, err := quicvarint.Read(br)
	if err != nil {
		return "", err
	}
	if frameType != FrameTypeTCPRequest {
		return "", fmt.Errorf("unexpected frame type 0x%x, expected 0x%x", frameType, FrameTypeTCPRequest)
	}

	addrLen, err := quicvarint.Read(br)
	if err != nil {
		return "", err
	}
	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(br, addrBytes); err != nil {
		return "", err
	}
	addr := string(addrBytes)

	paddingLen, err := quicvarint.Read(br)
	if err != nil {
		return "", err
	}
	if paddingLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(paddingLen)); err != nil {
			return "", err
		}
	}
	return addr, nil
}

// WriteTCPRequest writes a TCPRequest message to a QUIC stream.
func WriteTCPRequest(stream uquic.Stream, addr string) error {
	addrBytes := []byte(addr)
	addrLen := quicvarint.Len(uint64(len(addrBytes)))
	frameTypeLen := quicvarint.Len(FrameTypeTCPRequest)
	paddingLenVal := uint64(0) // No padding for now
	paddingLenLen := quicvarint.Len(paddingLenVal)

	// Allocate a buffer to write everything at once for efficiency
	buf := make([]byte, frameTypeLen+addrLen+len(addrBytes)+paddingLenLen+int(paddingLenVal))
	offset := 0

	offset += quicvarint.Encode(buf[offset:], FrameTypeTCPRequest)
	offset += quicvarint.Encode(buf[offset:], uint64(len(addrBytes)))
	copy(buf[offset:], addrBytes)
	offset += len(addrBytes)
	offset += quicvarint.Encode(buf[offset:], paddingLenVal)

	_, err := stream.Write(buf[:offset])
	return err
}

// ReadTCPResponse reads a TCPResponse message from a QUIC stream.
// [uint8] Status (0x00 = OK, 0x01 = Error)
// [varint] Message length
// [bytes] Message string
// [varint] Padding length
// [bytes] Random padding
func ReadTCPResponse(stream uquic.Stream) (bool, string, error) {
	br := bufio.NewReader(stream)

	statusByte, err := br.ReadByte()
	if err != nil {
		return false, "", err
	}
	ok := statusByte == 0x00

	msgLen, err := quicvarint.Read(br)
	if err != nil {
		return false, "", err
	}
	msgBytes := make([]byte, msgLen)
	if _, err := io.ReadFull(br, msgBytes); err != nil {
		return false, "", err
	}
	msg := string(msgBytes)

	paddingLen, err := quicvarint.Read(br)
	if err != nil {
		return false, "", err
	}
	if paddingLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(paddingLen)); err != nil {
			return false, "", err
		}
	}
	return ok, msg, nil
}

// WriteTCPResponse writes a TCPResponse message to a QUIC stream.
func WriteTCPResponse(stream uquic.Stream, ok bool, msg string) error {
	statusByte := byte(0x01) // Error
	if ok {
		statusByte = 0x00 // OK
	}

	msgBytes := []byte(msg)
	msgLen := uint64(len(msgBytes))
	paddingLenVal := uint64(0) // No padding for now

	// Calculate total size for buffer allocation
	bufLen := 1 + quicvarint.Len(msgLen) + len(msgBytes) + quicvarint.Len(paddingLenVal)
	buf := make([]byte, bufLen)
	offset := 0

	buf[offset] = statusByte
	offset++
	offset += quicvarint.Encode(buf[offset:], msgLen)
	copy(buf[offset:], msgBytes)
	offset += len(msgBytes)
	offset += quicvarint.Encode(buf[offset:], paddingLenVal)

	_, err := stream.Write(buf[:offset])
	return err
}

// UDPMessage format
// [uint32] Session ID
// [uint16] Packet ID
// [uint8] Fragment ID
// [uint8] Fragment count
// [varint] Address length
// [bytes] Address string (host:port)
// [bytes] Payload
type UDPMessage struct {
	SessionID     uint32
	PacketID      uint16
	FragmentID    uint8
	FragmentCount uint8
	Addr          string
	Data          []byte
}

// ParseUDPMessage parses a UDPMessage from a byte slice.
func ParseUDPMessage(b []byte) (*UDPMessage, error) {
	if len(b) < 8 { // Minimum header size without address and payload
		return nil, errors.New("UDPMessage: packet too short")
	}

	msg := &UDPMessage{}
	offset := 0

	msg.SessionID = binary.BigEndian.Uint32(b[offset : offset+4])
	offset += 4
	msg.PacketID = binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	msg.FragmentID = b[offset]
	offset += 1
	msg.FragmentCount = b[offset]
	offset += 1

	addrLen, n := quicvarint.Decode(b[offset:])
	if n <= 0 || offset+n > len(b) {
		return nil, errors.New("UDPMessage: failed to decode address length")
	}
	offset += n

	if offset+int(addrLen) > len(b) {
		return nil, errors.New("UDPMessage: address string out of bounds")
	}
	msg.Addr = string(b[offset : offset+int(addrLen)])
	offset += int(addrLen)

	msg.Data = b[offset:]

	return msg, nil
}

// Serialize serializes a UDPMessage into a byte slice. Returns the number of bytes written.
func (msg *UDPMessage) Serialize(buf []byte) int {
	addrBytes := []byte(msg.Addr)
	addrLenVarint := quicvarint.Len(uint64(len(addrBytes)))
	headerLen := 4 + 2 + 1 + 1 + addrLenVarint // SessionID + PacketID + FragmentID + FragmentCount + AddrLen
	totalLen := headerLen + len(addrBytes) + len(msg.Data)

	if len(buf) < totalLen {
		return -1 // Buffer too small
	}

	offset := 0
	binary.BigEndian.PutUint32(buf[offset:], msg.SessionID)
	offset += 4
	binary.BigEndian.PutUint16(buf[offset:], msg.PacketID)
	offset += 2
	buf[offset] = msg.FragmentID
	offset += 1
	buf[offset] = msg.FragmentCount
	offset += 1

	offset += quicvarint.Encode(buf[offset:], uint64(len(addrBytes)))
	copy(buf[offset:], addrBytes)
	offset += len(addrBytes)
	copy(buf[offset:], msg.Data)
	offset += len(msg.Data)

	return offset
}

// AuthRequest represents the authentication data parsed from an obfuscated HTTP request.
type AuthRequest struct {
	Auth string
	Rx   uint64 // Client's receive rate in bytes/sec
}

// AuthRequestFromObfuscated parses obfuscated authentication information from an HTTP request.
// This function needs to be kept in sync with client's buildAuthRequestObfuscatedHeaders.
func AuthRequestFromObfuscated(r *http.Request) AuthRequest {
	authReq := AuthRequest{}

	// Prioritize Authorization header for Auth string
	authH := r.Header.Get("Authorization")
	if strings.HasPrefix(authH, "Bearer ") {
		authReq.Auth = strings.TrimSpace(strings.TrimPrefix(authH, "Bearer "))
	} else {
		// Fallback to Cookie header
		cookieH := r.Header.Get("Cookie")
		if parts := strings.Split(cookieH, ";"); len(parts) > 0 {
			for _, part := range parts {
				if strings.Contains(part, "session_id=") {
					authReq.Auth = strings.TrimPrefix(strings.TrimSpace(part), "session_id=")
					break
				}
			}
		}
	}

	// Extract Rx (client receive rate) from obfuscated header
	if telemetryH := r.Header.Get("X-Client-Telemetry"); telemetryH != "" {
		var data struct {
			RxRate uint64 `json:"rx_rate"`
		}
		if err := json.Unmarshal([]byte(telemetryH), &data); err == nil {
			authReq.Rx = data.RxRate
		}
	} else if deviceCapH := r.Header.Get("X-Device-Capability"); deviceCapH != "" {
		var data struct {
			Bandwidth uint64 `json:"bandwidth"`
		}
		if err := json.Unmarshal([]byte(deviceCapH), &data); err == nil {
			authReq.Rx = data.Bandwidth
		}
	}

	// Restore the body for further reading (needed by other handlers like DecoyProxy)
	if r.Body != nil && r.ContentLength > 0 {
		bodyRaw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(bodyRaw)))
	}

	return authReq
}

// AuthResponse represents the authentication response sent back to the client.
type AuthResponse struct {
	UDPEnabled bool
	Rx         uint64 // Server's receive rate in bytes/sec
	RxAuto     bool   // If true, server declines to provide rate, client uses CC
}

// AuthResponseToHeader serializes the authentication response into HTTP headers.
// This needs to be kept in sync with client's AuthResponseFromHeader.
func AuthResponseToHeader(h http.Header, resp AuthResponse) {
	// Example: Embedding in a JSON response in X-Server-Telemetry
	// Or directly into X-Server-UDP-Enabled, X-Server-Rx-Rate headers
	// For simplicity, let's use custom headers here.
	h.Set("X-Server-UDP-Enabled", strconv.FormatBool(resp.UDPEnabled))
	if resp.RxAuto {
		h.Set("X-Server-Rx-Rate", "auto")
	} else {
		h.Set("X-Server-Rx-Rate", strconv.FormatUint(resp.Rx, 10))
	}
	// Add random padding headers if needed to mimic real traffic patterns
	// e.g., h.Set("X-Padding", generateRandomString(16))
}

// AuthResponseFromHeader parses the authentication response from HTTP headers.
// This needs to be kept in sync with server's AuthResponseToHeader.
func AuthResponseFromHeader(h http.Header) AuthResponse {
	resp := AuthResponse{}

	if udpEnabledStr := h.Get("X-Server-UDP-Enabled"); udpEnabledStr != "" {
		resp.UDPEnabled, _ = strconv.ParseBool(udpEnabledStr)
	}

	if rxRateStr := h.Get("X-Server-Rx-Rate"); rxRateStr != "" {
		if rxRateStr == "auto" {
			resp.RxAuto = true
		} else {
			resp.Rx, _ = strconv.ParseUint(rxRateStr, 10, 64)
		}
	}
	return resp
}

// ====================================================================
// 新增：Protocol 接口定义
// ====================================================================

// ProtocolData 是协议插件可以操作的数据的通用抽象。
// 具体类型由插件在实现时根据 Context 的 Type 字段进行类型断言。
type ProtocolData interface{}

// ProtocolContext 提供了关于当前操作上下文的信息。
type ProtocolContext struct {
	// Type 表示当前操作的数据类型，例如 "tcp_request", "udp_message", "auth_request", "auth_response"
	// 插件可以使用此字段进行类型断言
	Type string

	// IsClient 表示当前操作是否在客户端侧发生 (true for client, false for server)
	IsClient bool

	// PeerAddr 是对端的网络地址
	PeerAddr net.Addr

	// SessionID 仅对 UDP 消息有效
	SessionID uint32

	// StreamID 仅对 TCP Stream (QUIC Stream) 有效
	StreamID uquic.StreamID

	// 其他可能需要的上下文信息
	// 例如：connID, authID 等，如果插件需要这些信息来维护连接级别的状态
}

// Protocol 是协议插件需要实现的接口。
// 它提供在数据加密封装前修改和解密还原数据的方法。
type Protocol interface {
	// Name 返回插件的名称。
	Name() string

	// ParamName 返回插件参数的名称，用于配置。
	ParamName() string

	// Init 初始化协议插件。param 是用户配置的 ProtocolParam 字符串。
	// 如果初始化失败，返回错误。
	Init(param string) error

	// Obfuscate 在数据发送前，对协议内部字段进行修改。
	// data 是 ProtocolData，context 提供上下文信息。
	// 返回修改后的 data。如果返回错误，表示该操作应被中止。
	Obfuscate(data ProtocolData, context ProtocolContext) (ProtocolData, error)

	// Deobfuscate 在数据接收后，对协议内部字段进行还原。
	// data 是 ProtocolData，context 提供上下文信息。
	// 返回还原后的 data。如果返回错误，表示该操作应被中止。
	Deobfuscate(data ProtocolData, context ProtocolContext) (ProtocolData, error)
}

// ProtocolFactory 是用于创建 Protocol 实例的函数类型。
type ProtocolFactory func() Protocol

var (
	protocolFactories = make(map[string]ProtocolFactory)
	protocolMutex     sync.RWMutex
)

// RegisterProtocol 注册一个 Protocol 插件。
func RegisterProtocol(name string, factory ProtocolFactory) {
	protocolMutex.Lock()
	defer protocolMutex.Unlock()
	if _, exists := protocolFactories[name]; exists {
		panic("protocol: duplicate registration for " + name)
	}
	protocolFactories[name] = factory
}

// NewProtocol 根据名称和参数创建一个 Protocol 实例。
func NewProtocol(name string, param string) (Protocol, error) {
	protocolMutex.RLock()
	factory, ok := protocolFactories[name]
	protocolMutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("protocol: unknown protocol %q", name)
	}
	p := factory()
	if err := p.Init(param); err != nil {
		return nil, fmt.Errorf("protocol %q init failed: %w", name, err)
	}
	return p, nil
}

// ====================================================================
// 示例协议插件：SimpleAddrOffset (偏移 TCP 请求地址端口)
// ====================================================================

type SimpleAddrOffset struct {
	offset int // 端口偏移量
}

func (p *SimpleAddrOffset) Name() string { return "simple_addr_offset" }
func (p *SimpleAddrOffset) ParamName() string { return "port_offset" }

func (p *SimpleAddrOffset) Init(param string) error {
	offset, err := strconv.Atoi(param)
	if err != nil {
		return fmt.Errorf("invalid port_offset param %q: %w", param, err)
	}
	p.offset = offset
	return nil
}

func (p *SimpleAddrOffset) Obfuscate(data ProtocolData, ctx ProtocolContext) (ProtocolData, error) {
	if ctx.Type == "tcp_request" {
		reqAddr, ok := data.(string)
		if !ok {
			return nil, errors.New("simple_addr_offset: invalid data type for tcp_request")
		}
		host, portStr, err := net.SplitHostPort(reqAddr)
		if err != nil {
			return nil, fmt.Errorf("simple_addr_offset: invalid address format %q: %w", reqAddr, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("simple_addr_offset: invalid port %q: %w", portStr, err)
		}
		// 端口偏移
		newPort := port + p.offset
		if newPort < 1 || newPort > 65535 {
			return nil, fmt.Errorf("simple_addr_offset: port %d offset out of range (1-65535)", newPort)
		}
		return net.JoinHostPort(host, strconv.Itoa(newPort)), nil
	}
	// 不处理其他类型的数据
	return data, nil
}

func (p *SimpleAddrOffset) Deobfuscate(data ProtocolData, ctx ProtocolContext) (ProtocolData, error) {
	if ctx.Type == "tcp_request" { // 服务器端解密，还原客户端发来的请求
		reqAddr, ok := data.(string)
		if !ok {
			return nil, errors.New("simple_addr_offset: invalid data type for tcp_request")
		}
		host, portStr, err := net.SplitHostPort(reqAddr)
		if err != nil {
			return nil, fmt.Errorf("simple_addr_offset: invalid address format %q: %w", reqAddr, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("simple_addr_offset: invalid port %q: %w", portStr, err)
		}
		// 端口还原
		originalPort := port - p.offset
		if originalPort < 1 || originalPort > 65535 {
			return nil, fmt.Errorf("simple_addr_offset: port %d offset out of range (1-65535) during deobfuscation", originalPort)
		}
		return net.JoinHostPort(host, strconv.Itoa(originalPort)), nil
	}
	// 不处理其他类型的数据
	return data, nil
}

func init() {
	RegisterProtocol("simple_addr_offset", func() Protocol { return &SimpleAddrOffset{} })
}

// Some helper functions that might be needed from quic-go/internal/wire or similar
// For simplicity, assume a quicvarint.go exists or integrate a simple varint encoder/decoder
// If not, you'll need to implement these.
// Example simple varint (NOT PRODUCTION-READY, for illustration only):
// In a real project, import from `github.com/lucas-clemente/quic-go/internal/wire/varint.go` or similar.
var quicvarint quicVarint

type quicVarint struct{}

func (quicVarint) Read(r io.ByteReader) (uint64, error) {
	varint, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}
	return varint, nil
}

func (quicVarint) Encode(b []byte, i uint64) int {
	return binary.PutUvarint(b, i)
}

func (quicVarint) Len(i uint64) int {
	return binary.Uvarint(make([]byte, binary.MaxVarintLen64), i)
}
