package auth

import (
	"encoding/binary" // 用于处理字节序转换
	"errors"
	"fmt"
	"hash/crc32" // 用于 CRC32 校验
	// 导入核心协议接口包，并使用别名 protocol_ext
	protocol_ext "github.com/XLESSGo/XLESS/core/protocol"
	// 导入 internal/protocol 包以访问 UDPMessage 结构体
	protocol "github.com/XLESSGo/XLESS/core/internal/protocol"
)

const (
	// AuthAHeaderSize 定义了我们自定义头部的大小：CRC32 (4 字节) + 原始数据长度 (4 字节)
	AuthAHeaderSize = 8
)

// AuthAProtocol 实现了 protocol_ext.Protocol 接口
type AuthAProtocol struct {
	secret []byte // protocolParam 将被视为共享密钥
}

// Name 返回插件的名称。
func (p *AuthAProtocol) Name() string {
	return "auth_a"
}

// ParamName 返回插件参数的名称。
func (p *AuthAProtocol) ParamName() string {
	return "secret" // 我们预期有一个名为 "secret" 的参数
}

// Init 初始化插件。
func (p *AuthAProtocol) Init(param string) error {
	if param == "" {
		return errors.New("auth_a: 'secret' parameter cannot be empty")
	}
	p.secret = []byte(param)
	return nil
}

// Obfuscate 施加混淆逻辑。
func (p *AuthAProtocol) Obfuscate(data protocol_ext.ProtocolData, ctx protocol_ext.ProtocolContext) (protocol_ext.ProtocolData, error) {
	switch ctx.Type {
	case "tcp_request":
		// 对于 TCP 请求 (目标地址字符串)，暂时不做修改，直接透传。
		// SSR 类认证通常作用于实际数据载荷，而非目标地址字符串本身。
		return data, nil
	case "tcp_data":
		payload, ok := data.([]byte)
		if !ok {
			return nil, errors.New("auth_a: expected []byte for tcp_data")
		}
		if len(payload) == 0 {
			return []byte{}, nil // 如果载荷为空，返回空字节切片
		}

		return p.addAuthHeader(payload)

	case "udp_message":
		udpMsg, ok := data.(*protocol.UDPMessage)
		if !ok {
			return nil, errors.New("auth_a: expected *protocol.UDPMessage for udp_message")
		}
		if len(udpMsg.Data) == 0 {
			return udpMsg, nil // 如果 UDP 数据为空，直接返回消息，不添加头部
		}
		
		obfuscatedData, err := p.addAuthHeader(udpMsg.Data)
		if err != nil {
			return nil, err
		}
		udpMsg.Data = obfuscatedData
		return udpMsg, nil

	default:
		// 对于任何其他数据类型，直接透传。
		return data, nil
	}
}

// Deobfuscate 反转混淆逻辑。
func (p *AuthAProtocol) Deobfuscate(data protocol_ext.ProtocolData, ctx protocol_ext.ProtocolContext) (protocol_ext.ProtocolData, error) {
	switch ctx.Type {
	case "tcp_request":
		// 对于 TCP 请求，直接透传。
		return data, nil
	case "tcp_data":
		obfuscatedPayload, ok := data.([]byte)
		if !ok {
			return nil, errors.New("auth_a: expected []byte for tcp_data")
		}
		if len(obfuscatedPayload) < AuthAHeaderSize {
			return nil, errors.New("auth_a: tcp_data too short for header")
		}

		return p.removeAuthHeader(obfuscatedPayload)

	case "udp_message":
		udpMsg, ok := data.(*protocol.UDPMessage)
		if !ok {
			return nil, errors.New("auth_a: expected *protocol.UDPMessage for udp_message")
		}
		if len(udpMsg.Data) < AuthAHeaderSize {
			return nil, errors.New("auth_a: udp_message data too short for header")
		}

		originalData, err := p.removeAuthHeader(udpMsg.Data)
		if err != nil {
			return nil, err
		}
		udpMsg.Data = originalData
		return udpMsg, nil

	default:
		// 对于任何其他数据类型，直接透传。
		return data, nil
	}
}

// addAuthHeader 在载荷前添加 CRC32 校验和和原始数据长度。
func (p *AuthAProtocol) addAuthHeader(originalData []byte) ([]byte, error) {
	header := make([]byte, AuthAHeaderSize)

	// 计算 CRC32：crc32(secret + originalData)
	hasher := crc32.NewIEEE()
	_, _ = hasher.Write(p.secret)       // 先写入密钥
	_, _ = hasher.Write(originalData) // 再写入原始数据
	checksum := hasher.Sum32()
	binary.BigEndian.PutUint32(header[0:4], checksum) // 将 CRC32 写入头部前 4 字节

	// 写入原始数据长度
	// 检查原始数据长度是否超出 uint32 最大值
	if len(originalData) > 0xFFFFFFFF { 
		return nil, errors.New("auth_a: original data too large, exceeds uint32 max length")
	}
	binary.BigEndian.PutUint32(header[4:8], uint32(len(originalData))) // 将原始数据长度写入头部后 4 字节

	// 合并头部和原始数据
	return append(header, originalData...), nil
}

// removeAuthHeader 移除头部，验证 CRC32，并返回原始载荷。
func (p *AuthAProtocol) removeAuthHeader(obfuscatedData []byte) ([]byte, error) {
	// 提取头部
	header := obfuscatedData[0:AuthAHeaderSize]
	receivedChecksum := binary.BigEndian.Uint32(header[0:4])      // 读取接收到的 CRC32
	originalDataLen := binary.BigEndian.Uint32(header[4:8]) // 读取原始数据长度

	// 检查剩余数据长度是否与头部中声明的长度匹配
	if uint32(len(obfuscatedData)-AuthAHeaderSize) != originalDataLen {
		return nil, fmt.Errorf("auth_a: payload length mismatch: announced %d, actual %d",
			originalDataLen, len(obfuscatedData)-AuthAHeaderSize)
	}

	originalData := obfuscatedData[AuthAHeaderSize:]

	// 验证 CRC32
	hasher := crc32.NewIEEE()
	_, _ = hasher.Write(p.secret)       // 使用相同的密钥进行验证
	_, _ = hasher.Write(originalData) // 写入原始数据
	calculatedChecksum := hasher.Sum32()

	if receivedChecksum != calculatedChecksum {
		return nil, errors.New("auth_a: CRC32 checksum mismatch, authentication failed")
	}

	return originalData, nil
}

// init 函数用于注册 AuthAProtocol 插件。
func init() {
	protocol_ext.RegisterProtocol("auth_a", func() protocol_ext.Protocol {
		return &AuthAProtocol{}
	})
}
