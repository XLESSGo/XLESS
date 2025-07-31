// core/protocol/protocol.go
package protocol

import (
	"fmt"
	"net"
	"sync"

	uquic "github.com/XLESSGo/uquic" // 导入 uquic 包
	// 不要在这里导入 core/internal/protocol 的内容，而是直接依赖它
	_ "github.com/XLESSGo/XLESS/core/protocol/auth" // 导入 plugins 包，使其 init() 函数被执行
)

// ProtocolData is a generic abstraction for data that protocol plugins can operate on.
// The specific type is asserted by the plugin based on the Context's Type field.
type ProtocolData interface{}

// ProtocolContext provides information about the current operation context.
type ProtocolContext struct {
	// Type indicates the type of data being operated on, e.g., "tcp_request", "udp_message", "auth_request", "auth_response"
	// Plugins can use this field for type assertion.
	Type string

	// IsClient indicates whether the current operation is happening on the client side (true for client, false for server).
	IsClient bool

	// PeerAddr is the network address of the peer.
	PeerAddr net.Addr

	// SessionID is only valid for UDP messages.
	SessionID uint32

	// StreamID is only valid for TCP Streams (QUIC Streams).
	StreamID uquic.StreamID

	// Other context information that might be needed,
	// e.g., connID, authID, if plugins need this for connection-level state.
}

// Protocol is the interface that protocol plugins must implement.
// It provides methods to modify data before encryption/encapsulation and to restore data after decryption.
type Protocol interface {
	// Name returns the name of the plugin.
	Name() string

	// ParamName returns the name of the plugin's parameter, used for configuration.
	ParamName() string

	// Init initializes the protocol plugin. param is the ProtocolParam string configured by the user.
	// Returns an error if initialization fails.
	Init(param string) error

	// Obfuscate modifies internal protocol fields before data is sent (encrypted/encapsulated).
	// data is ProtocolData, context provides context information.
	// Returns the modified data. If an error is returned, the operation should be aborted.
	Obfuscate(data ProtocolData, context ProtocolContext) (ProtocolData, error)

	// Deobfuscate restores internal protocol fields after data is received (decrypted/de-encapsulated).
	// data is ProtocolData, context provides context information.
	// Returns the restored data. If an error is returned, the operation should be aborted.
	Deobfuscate(data ProtocolData, context ProtocolContext) (ProtocolData, error)
}

// ProtocolFactory is a function type for creating Protocol instances.
type ProtocolFactory func() Protocol

var (
	protocolFactories = make(map[string]ProtocolFactory)
	protocolMutex     sync.RWMutex
)

// RegisterProtocol registers a Protocol plugin.
func RegisterProtocol(name string, factory ProtocolFactory) {
	protocolMutex.Lock()
	defer protocolMutex.Unlock()
	if _, exists := protocolFactories[name]; exists {
		panic("protocol: duplicate registration for " + name)
	}
	protocolFactories[name] = factory
}

// NewProtocol creates a Protocol instance based on its name and parameters.
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
