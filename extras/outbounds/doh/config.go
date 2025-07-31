package doh // This package declaration must match the other files in the doh folder

import "time"

// UpstreamConfig represents a single upstream server configuration.
type UpstreamConfig struct {
	URL    string `toml:"url"` // URL of the upstream DoH server
	Weight int32  `toml:"weight"` // Weight for weighted load balancing
}

// UpstreamSectionConfig represents the 'upstream' section of the DoH configuration.
type UpstreamSectionConfig struct {
	UpstreamSelector string           `toml:"upstream_selector"` // Type of upstream selector (e.g., "random", "weighted_round_robin")
	UpstreamIETF     []UpstreamConfig `toml:"upstream_ietf"`     // List of IETF-style DoH upstreams
	UpstreamGoogle   []UpstreamConfig `toml:"upstream_google"`   // List of Google-style DoH upstreams
}

// OtherConfig represents the 'other' section of the DoH configuration, for miscellaneous settings.
type OtherConfig struct {
	NoECS                 bool          `toml:"no_ecs"`                 // Disable EDNS0-Client-Subnet
	NoIPv6                bool          `toml:"no_ipv6"`                // Disable IPv6 when querying upstream
	NoUserAgent           bool          `toml:"no_user_agent"`          // Disable submitting User-Agent header
	Verbose               bool          `toml:"verbose"`                // Enable verbose logging
	InsecureTLSSkipVerify bool          `toml:"insecure_tls_skip_verify"` // Skip TLS certificate verification (DANGEROUS IN PRODUCTION)
	Timeout               time.Duration `toml:"timeout"`                // Global timeout for HTTP requests made by the client
}

// Config represents the overall configuration structure for the DoH client/server.
// This struct is used by doh.NewClient to initialize the DoH client.
type Config struct {
	Listen   []string              `toml:"listen"` // Listen addresses for the DoH server (not directly used by client part)
	Upstream UpstreamSectionConfig `toml:"upstream"` // Upstream server configurations
	Other    OtherConfig           `toml:"other"`    // Other miscellaneous settings
}
