package obfs

import (
	"fmt"
)

// Obfuscator is the interface that wraps the Obfuscate and Deobfuscate methods.
// Both methods return the number of bytes written to out.
// If a packet is not valid, the methods should return 0.
type Obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

// ObfuscatorConfig defines the common configuration structure for all obfuscators.
// This allows for unified configuration parsing.
type ObfuscatorConfig struct {
	Type     string `mapstructure:"type"`     // Type of the obfuscator (e.g., "salamander", "scramble", "chameleon", "stealthflow", "quantumshuffle")
	Password string `mapstructure:"password"` // Pre-shared key/password used by the obfuscator
	// Add other common or specific configuration fields here if needed for future obfuscators.
	// For example, a "FakeHost" for StealthFlow, or a "Seed" for QuantumShuffle if it were stateful.
}

// NewObfuscatorFromConfig is a factory function that creates and returns an Obfuscator
// interface instance based on the provided configuration.
// It centralizes the instantiation logic for different obfuscation protocols.
func NewObfuscatorFromConfig(cfg ObfuscatorConfig) (Obfuscator, error) {
	switch cfg.Type {
	case "", "plain": // "plain" or empty type means no obfuscation
		return nil, nil // Return nil Obfuscator, indicating no obfuscation
	case "salamander":
		return NewSalamanderObfuscator([]byte(cfg.Password))
	case "ssh":
		return NewSshObfuscator([]byte(cfg.Password))
	case "dtls":
		return NewDtlsObfuscator([]byte(cfg.Password))
	case "dns":
		return NewDnsObfuscator([]byte(cfg.Password))
	default:
		return nil, fmt.Errorf("unknown obfuscator type: %s", cfg.Type)
	}
}
