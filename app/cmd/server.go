package cmd

import (
	"context"
	"crypto/tls" // Explicitly import standard library tls
	utls "github.com/refraction-networking/utls" // Import utls and alias it
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/libdns/gandi"
	"github.com/libdns/godaddy"
	"github.com/libdns/namedotcom"
	"github.com/libdns/vultr"
	acmev2 "github.com/mholt/acmez/v3/acme" // <-- Ensure acmez/v2/acme is used
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	protean "github.com/XLESSGo/protean"
	"go.uber.org/zap"
	"github.com/XLESSGo/uquic"

	"github.com/XLESSGo/XLESS/app/internal/utils"
	"github.com/XLESSGo/XLESS/core/server"
	"github.com/XLESSGo/XLESS/extras/auth"
	"github.com/XLESSGo/XLESS/extras/correctnet"
	"github.com/XLESSGo/XLESS/extras/masq"
	"github.com/XLESSGo/XLESS/extras/obfs" // Import obfs package
	"github.com/XLESSGo/XLESS/extras/outbounds"
	"github.com/XLESSGo/XLESS/extras/sniff"
	"github.com/XLESSGo/XLESS/extras/trafficlogger"
	eUtils "github.com/XLESSGo/XLESS/extras/utils"
)

const (
	defaultListenAddr = ":443"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Server mode",
	Run:   runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

type serverConfig struct {
	Listen                string                      `mapstructure:"listen"`
	Obfs                  serverConfigObfs            `mapstructure:"obfs"` // Modified here, use the new serverConfigObfs
	TLS                   *serverConfigTLS            `mapstructure:"tls"`
	ACME                  *serverConfigACME           `mapstructure:"acme"`
	QUIC                  serverConfigQUIC            `mapstructure:"quic"`
	Bandwidth             serverConfigBandwidth       `mapstructure:"bandwidth"`
	IgnoreClientBandwidth bool                        `mapstructure:"ignoreClientBandwidth"`
	SpeedTest             bool                        `mapstructure:"speedTest"`
	DisableUDP            bool                        `mapstructure:"disableUDP"`
	UDPIdleTimeout        time.Duration               `mapstructure:"udpIdleTimeout"`
	Auth                  serverConfigAuth            `mapstructure:"auth"`
	Resolver              serverConfigResolver        `mapstructure:"resolver"`
	Sniff                 serverConfigSniff           `mapstructure:"sniff"`
	ACL                   serverConfigACL             `mapstructure:"acl"`
	Outbounds             []serverConfigOutboundEntry `mapstructure:"outbounds"`
	TrafficStats          serverConfigTrafficStats    `mapstructure:"trafficStats"`
	Masquerade            serverConfigMasquerade      `mapstructure:"masquerade"`
	DecoyURL              string                      `mapstructure:"decoyURL"` // New field
	EnableUQUIC           bool                        `mapstructure:"enableUQUIC"`   // 从 serverConfigQUIC 移到这里
	UQUICSpecID           quic.QUICID                 `mapstructure:"uquicSpecID"` // 从 serverConfigQUIC 移到这里
	Protocol              string                      `mapstructure:"protocol"`
	ProtocolParam         string                      `mapstructure:"protocolParam"`
}

// serverConfigObfs struct now directly embeds obfs.ObfuscatorConfig
// The `mapstructure:",squash"` tag makes fields of obfs.ObfuscatorConfig directly exposed at the serverConfigObfs level
type serverConfigObfs struct {
	obfs.ObfuscatorConfig `mapstructure:",squash"`
}

type serverConfigTLS struct {
	Cert     string `mapstructure:"cert"`
	Key      string `mapstructure:"key"`
	SNIGuard string `mapstructure:"sniGuard"` // "disable", "dns-san", "strict"
}

type serverConfigACME struct {
	// Common fields
	Domains    []string `mapstructure:"domains"`
	Email      string   `mapstructure:"email"`
	CA         string   `mapstructure:"ca"`
	ListenHost string   `mapstructure:"listenHost"`
	Dir        string   `mapstructure:"dir"`

	// Type selection
	Type string               `mapstructure:"type"`
	HTTP serverConfigACMEHTTP `mapstructure:"http"`
	TLS  serverConfigACMETLS  `mapstructure:"tls"`
	DNS  serverConfigACMEDNS  `mapstructure:"dns"`

	// Legacy fields for backwards compatibility
	// Only applicable when Type is empty
	DisableHTTP    bool `mapstructure:"disableHTTP"`
	DisableTLSALPN bool `mapstructure:"disableTLSALPN"`
	AltHTTPPort    int  `mapstructure:"altHTTPPort"`
	AltTLSALPNPort int  `mapstructure:"altTLSALPNPort"`
}

type serverConfigACMEHTTP struct {
	AltPort int `mapstructure:"altPort"`
}

type serverConfigACMETLS struct {
	AltPort int `mapstructure:"altPort"`
}

type serverConfigACMEDNS struct {
	Name   string            `mapstructure:"name"`
	Config map[string]string `mapstructure:"config"`
}

type serverConfigQUIC struct {
	InitStreamReceiveWindow     uint64        `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64        `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64        `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64        `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration `mapstructure:"maxIdleTimeout"`
	MaxIncomingStreams          int64         `mapstructure:"maxIncomingStreams"`
	DisablePathMTUDiscovery     bool          `mapstructure:"disablePathMTUDiscovery"`
}

type serverConfigBandwidth struct {
	Up   string `mapstructure:"up"`
	Down string `mapstructure:"down"`
}

type serverConfigAuthHTTP struct {
	URL      string `mapstructure:"url"`
	Insecure bool   `mapstructure:"insecure"`
}

type serverConfigAuth struct {
	Type     string               `mapstructure:"type"`
	Password string               `mapstructure:"password"`
	UserPass map[string]string    `mapstructure:"userpass"`
	HTTP     serverConfigAuthHTTP `mapstructure:"http"`
	Command  string               `mapstructure:"command"`
}

type serverConfigResolverTCP struct {
	Addr    string        `mapstructure:"addr"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type serverConfigResolverUDP struct {
	Addr    string        `mapstructure:"addr"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type serverConfigResolverTLS struct {
	Addr     string        `mapstructure:"addr"`
	Timeout  time.Duration `mapstructure:"timeout"`
	SNI      string        `mapstructure:"sni"`
	Insecure bool          `mapstructure:"insecure"`
}

type serverConfigResolverHTTPS struct {
	Addr     string        `mapstructure:"addr"`
	Timeout  time.Duration `mapstructure:"timeout"`
	SNI      string        `mapstructure:"sni"`
	Insecure bool          `mapstructure:"insecure"`
}

type serverConfigResolver struct {
	Type  string                    `mapstructure:"type"`
	TCP   serverConfigResolverTCP   `mapstructure:"tcp"`
	UDP   serverConfigResolverUDP   `mapstructure:"udp"`
	TLS   serverConfigResolverTLS   `mapstructure:"tls"`
	HTTPS serverConfigResolverHTTPS `mapstructure:"https"`
}

type serverConfigSniff struct {
	Enable        bool          `mapstructure:"enable"`
	Timeout       time.Duration `mapstructure:"timeout"`
	RewriteDomain bool          `mapstructure:"rewriteDomain"`
	TCPPorts      string        `mapstructure:"tcpPorts"`
	UDPPorts      string        `mapstructure:"udpPorts"`
}

type serverConfigACL struct {
	File              string        `mapstructure:"file"`
	Inline            []string      `mapstructure:"inline"`
	GeoIP             string        `mapstructure:"geoip"`
	GeoSite           string        `mapstructure:"geosite"`
	GeoUpdateInterval time.Duration `mapstructure:"geoUpdateInterval"`
}

type serverConfigOutboundDirect struct {
	Mode       string `mapstructure:"mode"`
	BindIPv4   string `mapstructure:"bindIPv4"`
	BindIPv6   string `mapstructure:"bindIPv6"`
	BindDevice string `mapstructure:"bindDevice"`
	FastOpen   bool   `mapstructure:"fastOpen"`
}

type serverConfigOutboundSOCKS5 struct {
	Addr     string `mapstructure:"addr"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type serverConfigOutboundHTTP struct {
	URL      string `mapstructure:"url"`
	Insecure bool   `mapstructure:"insecure"`
}

type serverConfigOutboundEntry struct {
	Name   string                     `mapstructure:"name"`
	Type   string                     `mapstructure:"type"`
	Direct serverConfigOutboundDirect `mapstructure:"direct"`
	SOCKS5 serverConfigOutboundSOCKS5 `mapstructure:"socks5"`
	HTTP   serverConfigOutboundHTTP   `mapstructure:"http"`
}

type serverConfigTrafficStats struct {
	Listen string `mapstructure:"listen"`
	Secret string `mapstructure:"secret"`
}

type serverConfigMasqueradeFile struct {
	Dir string `mapstructure:"dir"`
}

type serverConfigMasqueradeProxy struct {
	URL         string `mapstructure:"url"`
	RewriteHost bool   `mapstructure:"rewriteHost"`
	Insecure    bool   `mapstructure:"insecure"`
}

type serverConfigMasqueradeString struct {
	Content    string            `mapstructure:"content"`
	Headers    map[string]string `mapstructure:"headers"`
	StatusCode int               `mapstructure:"statusCode"`
}

type serverConfigMasquerade struct {
	Type        string                       `mapstructure:"type"`
	File        serverConfigMasqueradeFile   `mapstructure:"file"`
	Proxy       serverConfigMasqueradeProxy  `mapstructure:"proxy"`
	String      serverConfigMasqueradeString `mapstructure:"string"`
	ListenHTTP  string                       `mapstructure:"listenHTTP"`
	ListenHTTPS string                       `mapstructure:"listenHTTPS"`
	ForceHTTPS  bool                         `mapstructure:"forceHTTPS"`
}

func (c *serverConfig) fillConn(hyConfig *server.Config) error {
	listenAddr := c.Listen
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}
	uAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	conn, err := correctnet.ListenUDP("udp", uAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}

	var ob obfs.Obfuscator
	// Use factory function from obfs package to create obfuscator
	ob, err = obfs.NewObfuscatorFromConfig(c.Obfs.ObfuscatorConfig) // Directly pass embedded ObfuscatorConfig
	if err != nil {
		return configError{Field: "obfs", Err: err} // Error message can be more generic
	}

	if ob == nil {
		hyConfig.Conn = conn
	} else {
		hyConfig.Conn = obfs.WrapPacketConn(conn, ob)
	}
	return nil
}

// 2. 修改 fillUQUICConfig 方法，直接赋值给 hyConfig
func (c *serverConfig) fillUQUICConfig(hyConfig *server.Config) error {
	hyConfig.EnableUQUIC = c.EnableUQUIC   // 直接赋值给 hyConfig
	hyConfig.UQUICSpecID = c.UQUICSpecID // 直接赋值给 hyConfig
	return nil
}

func (c *serverConfig) fillTLSConfig(hyConfig *server.Config) error {
	// If both TLS and ACME are unset, fallback to protean mimic cert
	if c.TLS == nil && c.ACME == nil {
		// Extract decoy host from DecoyURL
		decoyURL := c.DecoyURL
		decoyHost := ""
		if decoyURL != "" {
			u, err := url.Parse(decoyURL)
			if err == nil && u.Host != "" {
				decoyHost = u.Host
			}
		}
		if decoyHost == "" {
			return configError{Field: "decoyURL", Err: errors.New("cannot generate mimic cert: missing or invalid decoyURL")}
		}
		// Remove port if present
		if colon := strings.Index(decoyHost, ":"); colon != -1 {
			decoyHost = decoyHost[:colon]
		}

		// Generate mimic TLS certificate using protean for decoyHost
		// protean.MimicTLSCertificate returns *crypto/tls.Certificate
		stdCert, err := protean.MimicTLSCertificate([]string{decoyHost}, 365)
		if err != nil {
			return configError{Field: "tls", Err: fmt.Errorf("failed to generate mimic certificate: %w", err)}
		}

		// Convert *crypto/tls.Certificate to utls.Certificate (逐字段复制)
		utlsCert := utls.Certificate{
			Certificate: stdCert.Certificate,
			PrivateKey:  stdCert.PrivateKey,
			Leaf:        stdCert.Leaf,
			// OCSPStaple and SignedCertificateTimestamps usually not needed for client-side use in utls config
		}
		hyConfig.TLSConfig.Certificates = []utls.Certificate{utlsCert} // Use converted utlsCert

		// Wrap GetCertificate: Always return the pre-generated mimic certificate
		hyConfig.TLSConfig.GetCertificate = func(info *utls.ClientHelloInfo) (*utls.Certificate, error) {
			return &utlsCert, nil // Return address of converted utlsCert
		}
		return nil
	}
	// If both are set, error
	if c.TLS != nil && c.ACME != nil {
		return configError{Field: "tls", Err: errors.New("cannot set both tls and acme")}
	}
	// If TLS is set
	if c.TLS != nil {
		// SNI guard
		var sniGuard utils.SNIGuardFunc
		switch strings.ToLower(c.TLS.SNIGuard) {
		case "", "dns-san":
			sniGuard = utils.SNIGuardDNSSAN
		case "strict":
			sniGuard = utils.SNIGuardStrict
		case "disable":
			sniGuard = nil
		default:
			return configError{Field: "tls.sniGuard", Err: errors.New("unsupported SNI guard")}
		}
		// Local TLS cert
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return configError{Field: "tls", Err: errors.New("empty cert or key path")}
		}
		certLoader := &utils.LocalCertificateLoader{
			CertFile: c.TLS.Cert,
			KeyFile:  c.TLS.Key,
			SNIGuard: sniGuard,
		}
		// Try loading the cert-key pair here to catch errors early
		// (e.g. invalid files or insufficient permissions)
		err := certLoader.InitializeCache()
		if err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				if pathErr.Path == c.TLS.Cert {
					return configError{Field: "tls.cert", Err: pathErr}
				}
				if pathErr.Path == c.TLS.Key {
					return configError{Field: "tls.key", Err: pathErr}
				}
			}
			return configError{Field: "tls", Err: err}
		}
		// Use GetCertificate instead of Certificates so that
		// users can update the cert without restarting the server.
		// Wrap the crypto/tls.GetCertificate to return utls.Certificate
		hyConfig.TLSConfig.GetCertificate = func(utlsClientHello *utls.ClientHelloInfo) (*utls.Certificate, error) {
			// **FIX for original error: utlsClientHello.ClientHelloInfo undefined**
			// **最新修复 (针对 385 行错误): certLoader.GetCertificate 期望接收 *utls.ClientHelloInfo 并返回 *utls.Certificate。**
			// 直接将 utlsClientHello 传递给 certLoader.GetCertificate
			utlsCert, err := certLoader.GetCertificate(utlsClientHello) // 修复后的第 385 行
			if err != nil {
				return nil, err
			}
			return utlsCert, nil // 直接返回 utlsCert，无需额外转换
		}
		return nil
	}
	// If ACME is set
	if c.ACME != nil {
		dataDir := c.ACME.Dir
		if dataDir == "" {
			// If not specified in the config, check the environment variable
			// before resorting to the default "acme" value. The main reason
			// we have this is so that our setup script can set it to the
			// user's home directory.
			dataDir = envOrDefaultString(appACMEDirEnv, "acme")
		}
		cmCfg := &certmagic.Config{
			RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
			KeySource:          certmagic.DefaultKeyGenerator,
			Storage:            &certmagic.FileStorage{Path: dataDir},
			Logger:             logger,
		}
		cmIssuer := certmagic.NewACMEIssuer(cmCfg, certmagic.ACMEIssuer{
			Email:      c.ACME.Email,
			Agreed:     true,
			ListenHost: c.ACME.ListenHost,
			Logger:     logger,
		})
		switch strings.ToLower(c.ACME.CA) {
		case "letsencrypt", "le", "":
			// Default to Let's Encrypt
			cmIssuer.CA = certmagic.LetsEncryptProductionCA
		case "zerossl", "zero":
			cmIssuer.CA = certmagic.ZeroSSLProductionCA
			// Pass the correct acmev2.EAB type
			eab, err := genZeroSSLEAB(c.ACME.Email)
			if err != nil {
				return configError{Field: "acme.ca", Err: err}
			}
			cmIssuer.ExternalAccount = eab // Assign the correct acmev2.EAB
		default:
			return configError{Field: "acme.ca", Err: errors.New("unsupported CA")}
		}

		switch strings.ToLower(c.ACME.Type) {
		case "http":
			cmIssuer.DisableHTTPChallenge = false
			cmIssuer.DisableTLSALPNChallenge = true
			cmIssuer.DNS01Solver = nil
			cmIssuer.AltHTTPPort = c.ACME.HTTP.AltPort
		case "tls":
			cmIssuer.DisableHTTPChallenge = true
			cmIssuer.DisableTLSALPNChallenge = false
			cmIssuer.DNS01Solver = nil
			cmIssuer.AltTLSALPNPort = c.ACME.TLS.AltPort
		case "dns":
			cmIssuer.DisableHTTPChallenge = true
			cmIssuer.DisableTLSALPNChallenge = true
			if c.ACME.DNS.Name == "" {
				return configError{Field: "acme.dns.name", Err: errors.New("empty DNS provider name")}
			}
			if c.ACME.DNS.Config == nil {
				return configError{Field: "acme.dns.config", Err: errors.New("empty DNS provider config")}
			}
			switch strings.ToLower(c.ACME.DNS.Name) {
			case "cloudflare":
				// DNSProvider field exists according to provided solvers.go
				cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
					DNSManager: certmagic.DNSManager{ // <-- 修改
						DNSProvider: &cloudflare.Provider{
							APIToken: c.ACME.DNS.Config["cloudflare_api_token"],
						},
					}, // <-- 修改
				}
			case "duckdns":
				// DNSProvider field exists according to provided solvers.go
				cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
					DNSManager: certmagic.DNSManager{ // <-- 修改
						DNSProvider: &duckdns.Provider{
							APIToken:       c.ACME.DNS.Config["duckdns_api_token"],
							OverrideDomain: c.ACME.DNS.Config["duckdns_override_domain"],
						},
					}, // <-- 修改
				}
			case "gandi":
				// DNSProvider field exists according to provided solvers.go
				cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
					DNSManager: certmagic.DNSManager{ // <-- 修改
						DNSProvider: &gandi.Provider{
							BearerToken: c.ACME.DNS.Config["gandi_api_token"],
						},
					}, // <-- 修改
				}
			case "godaddy":
				// DNSProvider field exists according to provided solvers.go
				cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
					DNSManager: certmagic.DNSManager{ // <-- 修改
						DNSProvider: &godaddy.Provider{
							APIToken: c.ACME.DNS.Config["godaddy_api_token"],
						},
					}, // <-- 修改
				}
			case "namedotcom":
				// DNSProvider field exists according to provided solvers.go
				cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
					DNSManager: certmagic.DNSManager{ // <-- 修改
						DNSProvider: &namedotcom.Provider{
							Token:  c.ACME.DNS.Config["namedotcom_token"],
							User:   c.ACME.DNS.Config["namedotcom_user"],
							Server: c.ACME.DNS.Config["namedotcom_server"],
						},
					}, // <-- 修改
				}
			case "vultr":
				// DNSProvider field exists according to provided solvers.go
				cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
					DNSManager: certmagic.DNSManager{ // <-- 修改
						DNSProvider: &vultr.Provider{
							APIToken: c.ACME.DNS.Config["vultr_api_token"],
						},
					}, // <-- 修改
				}
			default:
				return configError{Field: "acme.dns.name", Err: errors.New("unsupported DNS provider")}
			}
		case "":
			// Legacy compatibility mode
			cmIssuer.DisableHTTPChallenge = c.ACME.DisableHTTP
			cmIssuer.DisableTLSALPNChallenge = c.ACME.DisableTLSALPN
			cmIssuer.AltHTTPPort = c.ACME.AltHTTPPort
			cmIssuer.AltTLSALPNPort = c.ACME.AltTLSALPNPort
		default:
			return configError{Field: "acme.type", Err: errors.New("unsupported ACME type")}
		}

		cmCfg.Issuers = []certmagic.Issuer{cmIssuer}
		cmCache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return cmCfg, nil
			},
			Logger: logger,
		})
		cmCfg = certmagic.New(cmCache, *cmCfg)

		if len(c.ACME.Domains) == 0 {
			return configError{Field: "acme.domains", Err: errors.New("empty domains")}
		}
		err := cmCfg.ManageSync(context.Background(), c.ACME.Domains)
		if err != nil {
			return configError{Field: "acme.domains", Err: err}
		}
		// Wrap certmagic.GetCertificate (which returns crypto/tls.Certificate)
		// to return utls.Certificate for hyConfig.TLSConfig
		hyConfig.TLSConfig.GetCertificate = func(utlsClientHello *utls.ClientHelloInfo) (*utls.Certificate, error) {
			// **FIX for original error: utlsClientHello.ClientHelloInfo undefined**
			// cmCfg.GetCertificate expects *crypto/tls.ClientHelloInfo and returns *crypto/tls.Certificate.
			// So, extract the embedded standard ClientHelloInfo and convert the returned certificate.
			stdCHI := &tls.ClientHelloInfo{
				ServerName: utlsClientHello.ServerName,
				// Other fields from utlsClientHello can be copied if needed by cmCfg.GetCertificate,
				// but ServerName is typically sufficient for certificate selection.
			}
			stdCert, err := cmCfg.GetCertificate(stdCHI) // Use constructed std ClientHelloInfo
			if err != nil {
				return nil, err
			}
			// Convert *crypto/tls.Certificate to *utls.Certificate
			utlsCert := &utls.Certificate{
				Certificate: stdCert.Certificate,
				PrivateKey:  stdCert.PrivateKey,
				Leaf:        stdCert.Leaf,
				OCSPStaple:  stdCert.OCSPStaple,
				SignedCertificateTimestamps: stdCert.SignedCertificateTimestamps,
			}
			return utlsCert, nil // Return converted utlsCert
		}
		return nil
	}
	return nil
}

func (c *serverConfig) fillProtocolConfig(hyConfig *server.Config) error {
	// 根据 Protocol 类型进行不同的初始化
	switch strings.ToLower(c.Protocol) {
	case "", "default":
		// 默认协议，可能不需要额外设置，或者使用默认值
		hyConfig.Protocol = server.ProtocolTypeDefault // 假设 server.ProtocolTypeDefault 是一个常量
		hyConfig.ProtocolParam = ""
	// 添加更多 case 来处理其他协议类型
	default:
		return configError{Field: "protocol", Err: fmt.Errorf("unsupported protocol type: %s", c.Protocol)}
	}
	return nil
}

func (c *serverConfig) fillDecoyURL(hyConfig *server.Config) error {
	if c.DecoyURL == "" {
		return configError{Field: "decoyURL", Err: errors.New("decoyURL is empty")}
	}
	hyConfig.DecoyURL = c.DecoyURL
	return nil
}

// genZeroSSLEAB now returns acmev2.EAB
func genZeroSSLEAB(email string) (*acmev2.EAB, error) {
	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.zerossl.com/acme/eab-credentials-email",
		strings.NewReader(url.Values{"email": []string{email}}.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to creare ZeroSSL EAB request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", certmagic.UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send ZeroSSL EAB request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed decoding ZeroSSL EAB API response: %w", err)
	}
	if result.Error.Code != 0 {
		return nil, fmt.Errorf("failed getting ZeroSSL EAB credentials: HTTP %d: %s (code %d)", resp.StatusCode, result.Error.Type, result.Error.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
	}

	return &acmev2.EAB{ // <-- Use acmev2.EAB here
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, nil
}

func (c *serverConfig) fillQUICConfig(hyConfig *server.Config) error {
	hyConfig.QUICConfig = server.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		MaxIncomingStreams:             c.QUIC.MaxIncomingStreams,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	return nil
}

func serverConfigOutboundDirectToOutbound(c serverConfigOutboundDirect) (outbounds.PluggableOutbound, error) {
	opts := outbounds.DirectOutboundOptions{}
	switch strings.ToLower(c.Mode) {
	case "", "auto":
		opts.Mode = outbounds.DirectOutboundModeAuto
	case "64":
		opts.Mode = outbounds.DirectOutboundMode64
	case "46":
		opts.Mode = outbounds.DirectOutboundMode46
	case "6":
		opts.Mode = outbounds.DirectOutboundMode6
	case "4":
		opts.Mode = outbounds.DirectOutboundMode4
	default:
		return nil, configError{Field: "outbounds.direct.mode", Err: errors.New("unsupported mode")}
	}
	bindIP := len(c.BindIPv4) > 0 || len(c.BindIPv6) > 0
	bindDevice := len(c.BindDevice) > 0
	if bindIP && bindDevice {
		return nil, configError{Field: "outbounds.direct", Err: errors.New("cannot bind both IP and device")}
	}
	if bindIP {
		ip4, ip6 := net.ParseIP(c.BindIPv4), net.ParseIP(c.BindIPv6)
		if len(c.BindIPv4) > 0 && ip4 == nil {
			return nil, configError{Field: "outbounds.direct.bindIPv4", Err: errors.New("invalid IPv4 address")}
		}
		if len(c.BindIPv6) > 0 && ip6 == nil {
			return nil, configError{Field: "outbounds.direct.bindIPv6", Err: errors.New("invalid IPv6 address")}
		}
		opts.BindIP4 = ip4
		opts.BindIP6 = ip6
	}
	if bindDevice {
		opts.DeviceName = c.BindDevice
	}
	opts.FastOpen = c.FastOpen
	return outbounds.NewDirectOutboundWithOptions(opts)
}

func serverConfigOutboundSOCKS5ToOutbound(c serverConfigOutboundSOCKS5) (outbounds.PluggableOutbound, error) {
	if c.Addr == "" {
		return nil, configError{Field: "outbounds.socks5.addr", Err: errors.New("empty socks5 address")}
	}
	return outbounds.NewSOCKS5Outbound(c.Addr, c.Username, c.Password), nil
}

func serverConfigOutboundHTTPToOutbound(c serverConfigOutboundHTTP) (outbounds.PluggableOutbound, error) {
	if c.URL == "" {
		return nil, configError{Field: "outbounds.http.url", Err: errors.New("empty http address")}
	}
	return outbounds.NewHTTPOutbound(c.URL, c.Insecure)
}

func (c *serverConfig) fillRequestHook(hyConfig *server.Config) error {
	if c.Sniff.Enable {
		s := &sniff.Sniffer{
			Timeout:       c.Sniff.Timeout,
			RewriteDomain: c.Sniff.RewriteDomain,
		}
		if c.Sniff.TCPPorts != "" {
			s.TCPPorts = eUtils.ParsePortUnion(c.Sniff.TCPPorts)
			if s.TCPPorts == nil {
				return configError{Field: "sniff.tcpPorts", Err: errors.New("invalid port union")}
			}
		}
		if c.Sniff.UDPPorts != "" {
			s.UDPPorts = eUtils.ParsePortUnion(c.Sniff.UDPPorts)
			if s.UDPPorts == nil {
				return configError{Field: "sniff.udpPorts", Err: errors.New("invalid port union")}
			}
		}
		hyConfig.RequestHook = s
	}
	return nil
}

func (c *serverConfig) fillOutboundConfig(hyConfig *server.Config) error {
	// Resolver, ACL, actual outbound are all implemented through the Outbound interface.
	// Depending on the config, we build a chain like this:
	// Resolver(ACL(Outbounds...))

	// Outbounds
	var obs []outbounds.OutboundEntry
	if len(c.Outbounds) == 0 {
		// Guarantee we have at least one outbound
		obs = []outbounds.OutboundEntry{{
			Name:     "default",
			Outbound: outbounds.NewDirectOutboundSimple(outbounds.DirectOutboundModeAuto),
		}}
	} else {
		obs = make([]outbounds.OutboundEntry, len(c.Outbounds))
		for i, entry := range c.Outbounds {
			if entry.Name == "" {
				return configError{Field: "outbounds.name", Err: errors.New("empty outbound name")}
			}
			var ob outbounds.PluggableOutbound
			var err error
			switch strings.ToLower(entry.Type) {
			case "direct":
				ob, err = serverConfigOutboundDirectToOutbound(entry.Direct)
			case "socks5":
				ob, err = serverConfigOutboundSOCKS5ToOutbound(entry.SOCKS5)
			case "http":
				ob, err = serverConfigOutboundHTTPToOutbound(entry.HTTP)
			default:
				err = configError{Field: "outbounds.type", Err: errors.New("unsupported outbound type")}
			}
			if err != nil {
				return err
			}
			obs[i] = outbounds.OutboundEntry{Name: entry.Name, Outbound: ob}
		}
	}

	var uOb outbounds.PluggableOutbound // "unified" outbound

	// ACL
	hasACL := false
	if c.ACL.File != "" && len(c.ACL.Inline) > 0 {
		return configError{Field: "acl", Err: errors.New("cannot set both acl.file and acl.inline")}
	}
	gLoader := &utils.GeoLoader{
		GeoIPFilename:   c.ACL.GeoIP,
		GeoSiteFilename: c.ACL.GeoSite,
		UpdateInterval:  c.ACL.GeoUpdateInterval,
		DownloadFunc:    geoDownloadFunc,
		DownloadErrFunc: geoDownloadErrFunc,
	}
	if c.ACL.File != "" {
		hasACL = true
		acl, err := outbounds.NewACLEngineFromFile(c.ACL.File, obs, gLoader)
		if err != nil {
			return configError{Field: "acl.file", Err: err}
		}
		uOb = acl
	} else if len(c.ACL.Inline) > 0 {
		hasACL = true
		acl, err := outbounds.NewACLEngineFromString(strings.Join(c.ACL.Inline, "\n"), obs, gLoader)
		if err != nil {
			return configError{Field: "acl.inline", Err: err}
		}
		uOb = acl
	} else {
		// No ACL, use the first outbound
		uOb = obs[0].Outbound
	}

	// Resolver
	switch strings.ToLower(c.Resolver.Type) {
	case "", "system":
		if hasACL {
			// If the user uses ACL, we must put a resolver in front of it,
			// for IP rules to work on domain requests.
			uOb = outbounds.NewSystemResolver(uOb)
		}
		// Otherwise we can just rely on outbound handling on its own.
	case "tcp":
		if c.Resolver.TCP.Addr == "" {
			return configError{Field: "resolver.tcp.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverTCP(c.Resolver.TCP.Addr, c.Resolver.TCP.Timeout, uOb)
	case "udp":
		if c.Resolver.UDP.Addr == "" {
			return configError{Field: "resolver.udp.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverUDP(c.Resolver.UDP.Addr, c.Resolver.UDP.Timeout, uOb)
	case "tls", "tcp-tls":
		if c.Resolver.TLS.Addr == "" {
			return configError{Field: "resolver.tls.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverTLS(c.Resolver.TLS.Addr, c.Resolver.TLS.Timeout, c.Resolver.TLS.SNI, c.Resolver.TLS.Insecure, uOb)
	case "https", "http":
		if c.Resolver.HTTPS.Addr == "" {
			return configError{Field: "resolver.https.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewDoHResolver(c.Resolver.HTTPS.Addr, c.Resolver.HTTPS.Timeout, c.Resolver.HTTPS.SNI, c.Resolver.HTTPS.Insecure, uOb)
	default:
		return configError{Field: "resolver.type", Err: errors.New("unsupported resolver type")}
	}

	// Speed test
	if c.SpeedTest {
		uOb = outbounds.NewSpeedtestHandler(uOb)
	}

	hyConfig.Outbound = &outbounds.PluggableOutboundAdapter{PluggableOutbound: uOb}
	return nil
}

func (c *serverConfig) fillBandwidthConfig(hyConfig *server.Config) error {
	var err error
	if c.Bandwidth.Up != "" {
		hyConfig.BandwidthConfig.MaxTx, err = utils.ConvBandwidth(c.Bandwidth.Up)
		if err != nil {
			return configError{Field: "bandwidth.up", Err: err}
		}
	}
	if c.Bandwidth.Down != "" {
		hyConfig.BandwidthConfig.MaxRx, err = utils.ConvBandwidth(c.Bandwidth.Down)
		if err != nil {
			return configError{Field: "bandwidth.down", Err: err}
		}
	}
	return nil
}

func (c *serverConfig) fillIgnoreClientBandwidth(hyConfig *server.Config) error {
	hyConfig.IgnoreClientBandwidth = c.IgnoreClientBandwidth
	return nil
}

func (c *serverConfig) fillDisableUDP(hyConfig *server.Config) error {
	hyConfig.DisableUDP = c.DisableUDP
	return nil
}

func (c *serverConfig) fillUDPIdleTimeout(hyConfig *server.Config) error {
	hyConfig.UDPIdleTimeout = c.UDPIdleTimeout
	return nil
}

func (c *serverConfig) fillAuthenticator(hyConfig *server.Config) error {
	if c.Auth.Type == "" {
		return configError{Field: "auth.type", Err: errors.New("empty auth type")}
	}
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		if c.Auth.Password == "" {
			return configError{Field: "auth.password", Err: errors.New("empty auth password")}
		}
		hyConfig.Authenticator = &auth.PasswordAuthenticator{Password: c.Auth.Password}
		return nil
	case "userpass":
		if len(c.Auth.UserPass) == 0 {
			return configError{Field: "auth.userpass", Err: errors.New("empty auth userpass")}
		}
		hyConfig.Authenticator = auth.NewUserPassAuthenticator(c.Auth.UserPass)
		return nil
	case "http", "https":
		if c.Auth.HTTP.URL == "" {
			return configError{Field: "auth.http.url", Err: errors.New("empty auth http url")}
		}
		hyConfig.Authenticator = auth.NewHTTPAuthenticator(c.Auth.HTTP.URL, c.Auth.HTTP.Insecure)
		return nil
	case "command", "cmd":
		if c.Auth.Command == "" {
			return configError{Field: "auth.command", Err: errors.New("empty auth command")}
		}
		hyConfig.Authenticator = &auth.CommandAuthenticator{Cmd: c.Auth.Command}
		return nil
	default:
		return configError{Field: "auth.type", Err: errors.New("unsupported auth type")}
	}
}

func (c *serverConfig) fillEventLogger(hyConfig *server.Config) error {
	hyConfig.EventLogger = &serverLogger{}
	return nil
}

func (c *serverConfig) fillTrafficLogger(hyConfig *server.Config) error {
	if c.TrafficStats.Listen != "" {
		tss := trafficlogger.NewTrafficStatsServer(c.TrafficStats.Secret)
		hyConfig.TrafficLogger = tss
		go runTrafficStatsServer(c.TrafficStats.Listen, tss)
	}
	return nil
}

// fillMasqHandler must be called after fillConn, as we may need to extract the QUIC
// port number from Conn for MasqTCPServer.
func (c *serverConfig) fillMasqHandler(hyConfig *server.Config) error {
	var handler http.Handler
	switch strings.ToLower(c.Masquerade.Type) {
	case "", "404":
		handler = http.NotFoundHandler()
	case "file":
		if c.Masquerade.File.Dir == "" {
			return configError{Field: "masquerade.file.dir", Err: errors.New("empty file directory")}
		}
		handler = http.FileServer(http.Dir(c.Masquerade.File.Dir))
	case "proxy":
		if c.Masquerade.Proxy.URL == "" {
			return configError{Field: "masquerade.proxy.url", Err: errors.New("empty proxy url")}
		}
		u, err := url.Parse(c.Masquerade.Proxy.URL)
		if err != nil {
			return configError{Field: "masquerade.proxy.url", Err: err}
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return configError{Field: "masquerade.proxy.url", Err: fmt.Errorf("unsupported protocol scheme \"%s\"", u.Scheme)}
		}
		transport := http.DefaultTransport
		if c.Masquerade.Proxy.Insecure {
			// If proxy is insecure, we need a custom Transport with InsecureSkipVerify
			// Note: This still uses crypto/tls for the proxy connection, not utls
			transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				// use default configs from http.DefaultTransport
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
		}
		handler = &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(u)
				// SetURL rewrites the Host header,
				// but we don't want that if rewriteHost is false
				if !c.Masquerade.Proxy.RewriteHost {
					r.Out.Host = r.In.Host
				}
			},
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				logger.Error("HTTP reverse proxy error", zap.Error(err))
				w.WriteHeader(http.StatusBadGateway)
			},
		}
	case "string":
		if c.Masquerade.String.Content == "" {
			return configError{Field: "masquerade.string.content", Err: errors.New("empty string content")}
		}
		if c.Masquerade.String.StatusCode != 0 &&
			(c.Masquerade.String.StatusCode < 200 ||
				c.Masquerade.String.StatusCode > 599 ||
				c.Masquerade.String.StatusCode == 233) {
			// 233 is reserved for xless authentication
			return configError{Field: "masquerade.string.statusCode", Err: errors.New("invalid status code (must be 200-599, except 233)")}
		}
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range c.Masquerade.String.Headers {
				w.Header().Set(k, v)
			}
			if c.Masquerade.String.StatusCode != 0 {
				w.WriteHeader(c.Masquerade.String.StatusCode)
			} else {
				w.WriteHeader(http.StatusOK) // Use 200 OK by default
			}
			_, _ = w.Write([]byte(c.Masquerade.String.Content))
		})
	default:
		return configError{Field: "masquerade.type", Err: errors.New("unsupported masquerade type")}
	}
	hyConfig.MasqHandler = &masqHandlerLogWrapper{H: handler, QUIC: true}

	if c.Masquerade.ListenHTTP != "" || c.Masquerade.ListenHTTPS != "" {
		if c.Masquerade.ListenHTTP != "" && c.Masquerade.ListenHTTPS == "" {
			return configError{Field: "masquerade.listenHTTPS", Err: errors.New("having only HTTP server without HTTPS is not supported")}
		}
		// **FIX for original error: cannot use hyConfig.TLSConfig (variable of struct type server.TLSConfig) as *"github.com/refraction-networking/utls".Config value in struct literal**
		// masq.MasqTCPServer.TLSConfig is *utls.Config.
		// hyConfig.TLSConfig is server.TLSConfig, which is a custom struct, not *utls.Config.
		// We need to create a *utls.Config instance and populate it from hyConfig.TLSConfig.
		utlsConfForMasq := &utls.Config{
			Certificates:   hyConfig.TLSConfig.Certificates,
			GetCertificate: hyConfig.TLSConfig.GetCertificate,
			// If server.TLSConfig had other fields relevant to utls.Config, they would be copied here.
			// Based on config.go, these are the only fields available in server.TLSConfig.
		}

		s := masq.MasqTCPServer{
			QUICPort:  extractPortFromAddr(hyConfig.Conn.LocalAddr().String()),
			HTTPSPort: extractPortFromAddr(c.Masquerade.ListenHTTPS),
			Handler:   &masqHandlerLogWrapper{H: handler, QUIC: false},
			TLSConfig: utlsConfForMasq, // Use the newly created *utls.Config instance
			ForceHTTPS: c.Masquerade.ForceHTTPS,
		}
		go runMasqTCPServer(&s, c.Masquerade.ListenHTTP, c.Masquerade.ListenHTTPS)
	}
	return nil
}

// Config validates the fields and returns a ready-to-use xless server config
func (c *serverConfig) Config() (*server.Config, error) {
	hyConfig := &server.Config{}
	fillers := []func(*server.Config) error{
		c.fillConn,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillRequestHook,
		c.fillOutboundConfig,
		c.fillBandwidthConfig,
		c.fillIgnoreClientBandwidth,
		c.fillDisableUDP,
		c.fillUDPIdleTimeout,
		c.fillAuthenticator,
		c.fillEventLogger,
		c.fillTrafficLogger,
		c.fillMasqHandler,
		c.fillDecoyURL,
		c.fillUQUICConfig, // 保持不变
		c.fillProtocolConfig, // <<< 新增这一行
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}

	return hyConfig, nil
}

func runServer(cmd *cobra.Command, args []string) {
	logger.Info("server mode")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read server config", zap.Error(err))
	}
	var config serverConfig
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse server config", zap.Error(err))
	}
	hyConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to load server config", zap.Error(err))
	}

	s, err := server.NewServer(hyConfig)
	if err != nil {
		logger.Fatal("failed to initialize server", zap.Error(err))
	}
	if config.Listen != "" {
		logger.Info("server up and running", zap.String("listen", config.Listen))
	} else {
		logger.Info("server up and running", zap.String("listen", defaultListenAddr))
	}

	if !disableUpdateCheck {
		go runCheckUpdateServer()
	}

	if err := s.Serve(); err != nil {
		logger.Fatal("failed to serve", zap.Error(err))
	}
}

func runTrafficStatsServer(listen string, handler http.Handler) {
	logger.Info("traffic stats server up and running", zap.String("listen", listen))
	if err := correctnet.HTTPListenAndServe(listen, handler); err != nil {
		logger.Fatal("failed to serve traffic stats", zap.Error(err))
	}
}

func runMasqTCPServer(s *masq.MasqTCPServer, httpAddr, httpsAddr string) {
	errChan := make(chan error, 2)
	if httpAddr != "" {
		go func() {
			logger.Info("masquerade HTTP server up and running", zap.String("listen", httpAddr))
			errChan <- s.ListenAndServeHTTP(httpAddr)
		}()
	}
	if httpsAddr != "" {
		go func() {
			logger.Info("masquerade HTTPS server up and running", zap.String("listen", httpsAddr))
			errChan <- s.ListenAndServeHTTPS(httpsAddr)
		}()
	}
	err := <-errChan
	if err != nil {
		logger.Fatal("failed to serve masquerade HTTP(S)", zap.Error(err))
	}
}

func geoDownloadFunc(filename, url string) {
	logger.Info("downloading database", zap.String("filename", filename), zap.String("url", url))
}

func geoDownloadErrFunc(err error) {
	if err != nil {
		logger.Error("failed to download database", zap.Error(err))
	}
}

type serverLogger struct{}

func (l *serverLogger) Connect(addr net.Addr, id string, tx uint64) {
	logger.Info("client connected", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint64("tx", tx))
}

func (l *serverLogger) Disconnect(addr net.Addr, id string, err error) {
	logger.Info("client disconnected", zap.String("addr", addr.String()), zap.String("id", id), zap.Error(err))
}

func (l *serverLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	logger.Debug("TCP request", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	if err == nil {
		logger.Debug("TCP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("TCP error", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *serverLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	logger.Debug("UDP request", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if err == nil {
		logger.Debug("UDP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID))
	} else {
		logger.Warn("UDP error", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.Error(err))
	}
}

type masqHandlerLogWrapper struct {
	H    http.Handler
	QUIC bool
}

func (m *masqHandlerLogWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Debug("masquerade request",
		zap.String("addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("url", r.URL.String()),
		zap.Bool("quic", m.QUIC))
	m.H.ServeHTTP(w, r)
}

func extractPortFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
