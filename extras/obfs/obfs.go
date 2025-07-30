package obfs

import (
	"fmt"

	hypernova "github.com/XLESSGo/XLESS/extras/obfs/hypernova"
	cosmicdust "github.com/XLESSGo/XLESS/extras/obfs/cosmicdust"
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
	case "scramble":
		return NewScrambleObfuscator([]byte(cfg.Password))
	case "chameleon":
		return NewChameleonObfuscator([]byte(cfg.Password))
	case "polymorph":
		return NewPolyMorphObfuscator([]byte(cfg.Password))
	case "timewarp":
		return NewTimeWarpObfuscator([]byte(cfg.Password))
	case "nebula":
		return NewNebulaObfuscator([]byte(cfg.Password))
	case "quantumshuffle":
		// For QuantumShuffle, the password is also used for key derivation and randomness seeding.
		return NewQuantumShuffleObfuscator([]byte(cfg.Password))
	case "hypernova":
		// Use the NewHypernovaObfuscator from the new hypernova package
		return hypernova.NewHypernovaObfuscator([]byte(cfg.Password))
	case "cosmicdust":
		// Use the NewCosmicDustObfuscator from the new cosmicdust package
		return cosmicdust.NewCosmicDustObfuscator([]byte(cfg.Password))
	default:
		return nil, fmt.Errorf("unknown obfuscator type: %s", cfg.Type)
	}
}



