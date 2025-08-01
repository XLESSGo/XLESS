module github.com/XLESSGo/XLESS/app

go 1.24.0

toolchain go1.24.5

require (
	github.com/XLESSGo/XLESS/core v0.0.0
	github.com/XLESSGo/XLESS/extras v0.0.0
	github.com/XLESSGo/protean v0.0.0
	github.com/XLESSGo/uquic v0.0.0
	github.com/XLESSGo/water v0.0.0
	github.com/apernet/go-tproxy v0.0.0-20230809025308-8f4723fd742f
	github.com/caddyserver/certmagic v0.22.1
	github.com/libdns/cloudflare v0.1.1
	github.com/libdns/duckdns v0.2.0
	github.com/libdns/gandi v1.0.3
	github.com/libdns/godaddy v1.0.3
	github.com/libdns/namedotcom v0.3.3
	github.com/libdns/vultr v1.0.0
	github.com/mdp/qrterminal/v3 v3.1.1
	github.com/mholt/acmez/v3 v3.1.1
	github.com/refraction-networking/utls v1.7.4-0.20250521174854-63aeec73c564
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.15.0
	github.com/stretchr/testify v1.10.0
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	go.uber.org/zap v1.27.0
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6
	golang.org/x/sys v0.33.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/bluele/gcache v0.0.2 // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/database64128/netx-go v0.0.0-20240905055117-62795b8b054a // indirect
	github.com/database64128/tfo-go/v2 v2.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20250501235452-c0086092b71a // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.6 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/infobloxopen/go-trees v0.0.0-20221216143356-66ceba885ebc // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/libdns/libdns v0.2.3 // indirect
	github.com/m13253/dns-over-https/v2 v2.3.10 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/miekg/dns v1.1.64 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/onsi/ginkgo/v2 v2.23.4 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/refraction-networking/clienthellod v0.5.0-alpha2 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	github.com/vultr/govultr/v3 v3.6.4 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/mock v0.5.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/oauth2 v0.20.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/qr v0.2.0 // indirect
)

replace github.com/XLESSGo/XLESS/core => ../core

replace github.com/XLESSGo/XLESS/extras => ../extras
