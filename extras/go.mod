module github.com/XLESSGo/XLESS/extras

go 1.24.0

toolchain go1.24.5

require (
	github.com/XLESSGo/XLESS/core v0.0.0-20250724143135-0a316cc69029
	github.com/XLESSGo/uquic v0.0.0
	github.com/babolivier/go-doh-client v0.0.0-20201028162107-a76cff4cb8b6
	github.com/database64128/tfo-go/v2 v2.2.2
	github.com/hashicorp/golang-lru/v2 v2.0.5
	github.com/miekg/dns v1.1.59
	github.com/refraction-networking/utls v1.7.4-0.20250521174854-63aeec73c564
	github.com/stretchr/testify v1.10.0
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	golang.org/x/crypto v0.38.0
	golang.org/x/net v0.40.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/apernet/quic-go v0.52.1-0.20250607183305-9320c9d14431 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/database64128/netx-go v0.0.0-20240905055117-62795b8b054a // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20250501235452-c0086092b71a // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/onsi/ginkgo/v2 v2.23.4 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/refraction-networking/clienthellod v0.5.0-alpha2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/apernet/hysteria/core/v2 => ../core
