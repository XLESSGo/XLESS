package obfs

import (
	"fmt"
)

// ObfuscatorConfig defines the common configuration for all obfuscators.
// It uses JSON tags for potential serialization/deserialization.
type ObfuscatorConfig struct {
	Type     string `json:"type" mapstructure:"type"`         // Obfuscator type, e.g., "salamander", "plain", "simple_xor"
	Password string `json:"password" mapstructure:"password"` // Password for obfuscators that require it (e.g., Salamander)
	// Add other common or specific fields for future obfuscators here.
	// For example:
	// KeyLength int `json:"keyLength" mapstructure:"keyLength"`
}

// NewObfuscatorFromConfig is a factory function that creates and returns an
// Obfuscator interface instance based on the provided ObfuscatorConfig.
func NewObfuscatorFromConfig(cfg ObfuscatorConfig) (Obfuscator, error) {
	switch cfg.Type {
	case "", "plain":
		// Return nil Obfuscator for "plain" or empty type, indicating no obfuscation.
		return nil, nil
	case "salamander":
		// Create and return a SalamanderObfuscator instance.
		return NewSalamanderObfuscator([]byte(cfg.Password))
	// TODO: Add cases for other obfuscator types here.
	// Example for a hypothetical "simple_xor" obfuscator:
	// case "simple_xor":
	//     // Assuming NewSimpleXORObfuscator takes a byte key, you'd convert cfg.Password or add a specific key field.
	//     if len(cfg.Password) == 0 {
	//         return nil, fmt.Errorf("simple_xor obfuscator requires a password (key)")
	//     }
	//     return NewSimpleXORObfuscator(cfg.Password[0]), nil // Example: use first byte of password as key
	default:
		return nil, fmt.Errorf("unknown obfuscator type: %s", cfg.Type)
	}
}

// Obfuscator is the interface that wraps the Obfuscate and Deobfuscate methods.
// Both methods return the number of bytes written to out.
// If a packet is not valid, the methods should return 0.
// This interface remains unchanged as it is already generic enough.
type Obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}
