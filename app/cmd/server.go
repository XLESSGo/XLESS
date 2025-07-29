package cmd

import (
	"context"
	"crypto/tls" // Explicitly import the standard library's tls
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
	acmev2 "github.com/mholt/acmez/v2/acme" // <-- Ensure using acmez/v2/acme
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	utls "github.com/refraction-networking/utls" // Import utls with an alias
	protean "github.com/XLESSGo/protean"
	"go.uber.org/zap"

	"github.com/XLESSGo/XLESS/app/internal/utils"
	"github.com/XLESSGo/XLESS/core/server"
	"github.com/XLESSGo/XLESS/extras/auth"
	"github.com/XLESSGo/XLESS/extras/correctnet"
	"github.com/XLESSGo/XLESS/extras/masq"
	"github.com/XLESSGo/XLESS/extras/transport"
	"github.com/XLESSGo/XLESS/extras/transport/protocol"
	hysteria "github.com/XLESSGo/XLESS/hysteria"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run XLESS server",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			// Support legacy command line usage
			if err := viper.Set("server", args[0]); err != nil {
				logger.Fatal("failed to set server address", zap.Error(err))
			}
		}
		if err := runServer(); err != nil {
			logger.Fatal("server run error", zap.Error(err))
		}
	},
}

const (
	serverCmdObfsFlag          = "obfs"
	serverCmdObfsPasswordFlag  = "obfs-password"
	serverCmdObfsEnableUDPFlag = "obfs-udp"
	serverCmdAuthFlag          = "auth"
	serverCmdAuthPasswordFlag  = "auth-password"
	serverCmdMasqueradeFlag    = "masquerade"
	serverCmdMasqueradeQUICFlag = "masquerade-quic"
	serverCmdResolverFlag      = "resolver"
	serverCmdCorrectNetFlag    = "correct-net"
)

func init() {
	// General flags
	serverCmd.Flags().StringP("config", "c", "./config.json", "config file")
	serverCmd.Flags().String("host", "0.0.0.0", "server listen host")
	serverCmd.Flags().Int("port", 3443, "server listen port")
	serverCmd.Flags().String("acme-email", "", "acme email")
	serverCmd.Flags().String("acme-domains", "", "acme domains, comma separated")
	serverCmd.Flags().String("acme-dns-provider", "", "acme dns provider")
	serverCmd.Flags().String("cert", "", "tls cert file")
	serverCmd.Flags().String("key", "", "tls key file")
	serverCmd.Flags().Bool("insecure", false, "insecure tls")
	serverCmd.Flags().String("server-name", "", "tls server name")
	// Bind general flags
	_ = viper.BindPFlag("server.host", serverCmd.Flags().Lookup("host"))
	_ = viper.BindPFlag("server.port", serverCmd.Flags().Lookup("port"))
	_ = viper.BindPFlag("server.tls.acme.email", serverCmd.Flags().Lookup("acme-email"))
	_ = viper.BindPFlag("server.tls.acme.domains", serverCmd.Flags().Lookup("acme-domains"))
	_ = viper.BindPFlag("server.tls.acme.dns.provider", serverCmd.Flags().Lookup("acme-dns-provider"))
	_ = viper.BindPFlag("server.tls.cert", serverCmd.Flags().Lookup("cert"))
	_ = viper.BindPFlag("server.tls.key", serverCmd.Flags().Lookup("key"))
	_ = viper.BindPFlag("server.tls.insecure", serverCmd.Flags().Lookup("insecure"))
	_ = viper.BindPFlag("server.tls.serverName", serverCmd.Flags().Lookup("server-name"))

	// Obfuscation flags
	serverCmd.Flags().String(serverCmdObfsFlag, "", "obfuscation type")
	serverCmd.Flags().String(serverCmdObfsPasswordFlag, "", "obfuscation password")
	serverCmd.Flags().Bool(serverCmdObfsEnableUDPFlag, false, "enable udp obfuscation")
	// Bind obfuscation flags
	_ = viper.BindPFlag("obfs.type", serverCmd.Flags().Lookup(serverCmdObfsFlag))
	_ = viper.BindPFlag("obfs.password", serverCmd.Flags().Lookup(serverCmdObfsPasswordFlag))
	_ = viper.BindPFlag("obfs.udp", serverCmd.Flags().Lookup(serverCmdObfsEnableUDPFlag))

	// Auth flags
	serverCmd.Flags().String(serverCmdAuthFlag, "", "auth type")
	serverCmd.Flags().String(serverCmdAuthPasswordFlag, "", "auth password")
	// Bind auth flags
	_ = viper.BindPFlag("auth.type", serverCmd.Flags().Lookup(serverCmdAuthFlag))
	_ = viper.BindPFlag("auth.password", serverCmd.Flags().Lookup(serverCmdAuthPasswordFlag))

	// Masquerade flags
	serverCmd.Flags().String(serverCmdMasqueradeFlag, "", "masquerade url")
	serverCmd.Flags().Bool(serverCmdMasqueradeQUICFlag, false, "enable quic masquerade")
	// Bind masquerade flags
	_ = viper.BindPFlag("masquerade.url", serverCmd.Flags().Lookup(serverCmdMasqueradeFlag))
	_ = viper.BindPFlag("masquerade.quic", serverCmd.Flags().Lookup(serverCmdMasqueradeQUICFlag))

	// CorrectNet flags
	serverCmd.Flags().String(serverCmdCorrectNetFlag, "", "correctnet url")
	// Bind CorrectNet flags
	_ = viper.BindPFlag("correct_net.url", serverCmd.Flags().Lookup(serverCmdCorrectNetFlag))

	// Other flags
	serverCmd.Flags().String(serverCmdResolverFlag, "", "custom dns resolver")
	// Bind other flags
	_ = viper.BindPFlag("resolver", serverCmd.Flags().Lookup(serverCmdResolverFlag))

	rootCmd.AddCommand(serverCmd)
}

func newCertmagicConfig(acmeConfig *server.ACMEConfig) (*certmagic.Config, error) {
	// DNS provider
	var dnsProvider certmagic.DNSProvider
	if acmeConfig.DNS.Provider != "" {
		prov, err := newCertmagicDNSProvider(acmeConfig.DNS)
		if err != nil {
			return nil, fmt.Errorf("dns provider error: %v", err)
		}
		dnsProvider = prov
	}
	// Default CA, email
	cfg := certmagic.NewDefault()
	if acmeConfig.CA != "" {
		cfg.CA = acmeConfig.CA
	}
	if acmeConfig.Email != "" {
		cfg.Email = acmeConfig.Email
	}
	// Disable HTTP and TLS-ALPN challenges if DNS challenge is enabled
	if dnsProvider != nil {
		cfg.Issuers = []certmagic.Issuer{
			certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
				CA:              cfg.CA,
				Email:           cfg.Email,
				DNS01Solver:     &certmagic.DNS01Solver{DNSProvider: dnsProvider},
				Challenges:      []acmev2.Challenge{acmev2.ChallengeTypeDNS01},
				DisableHTTPChall: true,
				DisableTLSALPNChall: true,
			}),
		}
	}
	// Manage domains
	domains := strings.Split(acmeConfig.Domains, ",")
	for i, domain := range domains {
		domains[i] = strings.TrimSpace(domain)
	}
	err := cfg.ManageSync(context.Background(), domains)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func newCertmagicDNSProvider(dnsConfig *server.DNSConfig) (certmagic.DNSProvider, error) {
	switch dnsConfig.Provider {
	case "cloudflare":
		return &cloudflare.Provider{
			APIToken: dnsConfig.Cloudflare.APIToken,
		}, nil
	case "godaddy":
		return &godaddy.Provider{
			APIToken: dnsConfig.GoDaddy.APIToken,
			APIKey:   dnsConfig.GoDaddy.APIKey,
		}, nil
	case "duckdns":
		return &duckdns.Provider{
			Token: dnsConfig.DuckDNS.Token,
		}, nil
	case "gandi":
		return &gandi.Provider{
			APIToken: dnsConfig.Gandi.APIToken,
		}, nil
	case "namedotcom":
		return &namedotcom.Provider{
			Username: dnsConfig.NameDotCom.Username,
			APIToken: dnsConfig.NameDotCom.APIToken,
		}, nil
	case "vultr":
		return &vultr.Provider{
			APIToken: dnsConfig.Vultr.APIToken,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported dns provider: %s", dnsConfig.Provider)
	}
}

// FIX 1: Correctly implement the GetCertificate function to bridge utls and certmagic.
// It now converts utls's ClientHelloInfo to the standard library's tls.ClientHelloInfo
// before calling certmagic.
func newCertmagicTLSConfig(cmCfg *certmagic.Config) *utls.Config {
	return &utls.Config{
		GetCertificate: func(info *utls.ClientHelloInfo) (*utls.Certificate, error) {
			// certmagic's GetCertificate expects a *tls.ClientHelloInfo.
			// We must construct one from the provided *utls.ClientHelloInfo.
			// The most critical field for certificate selection is ServerName.
			stdInfo := &tls.ClientHelloInfo{
				ServerName:        info.ServerName,
				Conn:              info.Conn, // Pass along the connection
				CipherSuites:      info.CipherSuites,
				SupportedCurves:   info.SupportedCurves,
				SupportedPoints:   info.SupportedPoints,
				SignatureSchemes:  info.SignatureSchemes,
				SupportedProtos:   info.SupportedProtos,
				SupportedVersions: info.SupportedVersions,
			}

			// Now, call certmagic with the standard library type.
			// The returned certificate is of type *tls.Certificate.
			cert, err := cmCfg.GetCertificate(stdInfo)
			if err != nil {
				return nil, err
			}

			// Because utls.Certificate is a type alias for tls.Certificate
			// (type Certificate = tls.Certificate), we can return it directly.
			// The compiler will treat them as the same type.
			return cert, nil
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func newObfuscator(obfsConfig *server.ObfsConfig) (hysteria.Obfuscator, error) {
	switch obfsConfig.Type {
	case "none", "":
		return nil, nil
	case "faketls":
		return protocol.NewFakeTLSObfuscator(obfsConfig.FakeTLS.Password), nil
	case "aes-gcm":
		key, err := utils.DeriveKey(obfsConfig.AESGCM.Password, 32)
		if err != nil {
			return nil, err
		}
		return protocol.NewAESGCMObfuscator(key), nil
	default:
		return nil, fmt.Errorf("unsupported obfuscator: %s", obfsConfig.Type)
	}
}

func newAuthenticator(authConfig *server.AuthConfig) (auth.Authenticator, error) {
	switch authConfig.Type {
	case "none", "":
		return nil, nil
	case "password":
		return auth.NewPasswordAuthenticator(authConfig.Password.Password, 32), nil
	case "github":
		return auth.NewGitHubAuthenticator(
			authConfig.GitHub.ClientID,
			authConfig.GitHub.ClientSecret,
			authConfig.GitHub.RedirectURL,
			authConfig.GitHub.Organization,
			authConfig.GitHub.Repo,
		), nil
	default:
		return nil, fmt.Errorf("unsupported authenticator: %s", authConfig.Type)
	}
}

func newMasqueradeHandler(masqConfig *server.MasqueradeConfig) (http.Handler, error) {
	u, err := url.Parse(masqConfig.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid masquerade url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported masquerade scheme: %s", u.Scheme)
	}
	return httputil.NewSingleHostReverseProxy(u), nil
}

func newCorrectNet(cnConfig *server.CorrectNetConfig) (correctnet.CorrectNet, error) {
	u, err := url.Parse(cnConfig.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid correctnet url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported correctnet scheme: %s", u.Scheme)
	}
	return correctnet.NewClient(u), nil
}

func newProtean(pConfig *server.ProteanConfig) (*protean.Config, error) {
	if pConfig == nil {
		return nil, nil
	}
	var c protean.Config
	switch pConfig.Type {
	case "none", "":
		return nil, nil
	case "obfs4":
		c.Shape = &protean.ShapeObfs4{
			EnableUDP: pConfig.Obfs4.EnableUDP,
		}
	case "fte":
		c.Shape = &protean.ShapeFTE{
			Regex:    pConfig.FTE.Regex,
			Capacity: pConfig.FTE.Capacity,
		}
	default:
		return nil, fmt.Errorf("unsupported protean type: %s", pConfig.Type)
	}
	return &c, nil
}

func runServer() error {
	// Load config
	configPath := viper.GetString("config")
	if configPath != "" {
		viper.SetConfigFile(configPath)
		if err := viper.ReadInConfig(); err != nil {
			return fmt.Errorf("failed to read config file: %v", err)
		}
	}

	// Unmarshal config
	var hyConfig server.Config
	if err := viper.Unmarshal(&hyConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Log config
	configContent, _ := json.Marshal(hyConfig)
	logger.Info("using config", zap.String("content", string(configContent)))

	// Hysteria config
	hysteriaConfig := &hysteria.Config{
		Logger: &serverLogger{},
	}

	// Obfuscator
	if hyConfig.Obfs != nil {
		obfs, err := newObfuscator(hyConfig.Obfs)
		if err != nil {
			return err
		}
		hysteriaConfig.Obfuscator = obfs
	}

	// Authenticator
	if hyConfig.Auth != nil {
		auth, err := newAuthenticator(hyConfig.Auth)
		if err != nil {
			return err
		}
		hysteriaConfig.Authenticator = auth
	}

	// Masquerade
	if hyConfig.Masquerade != nil {
		masqHandler, err := newMasqueradeHandler(hyConfig.Masquerade)
		if err != nil {
			return err
		}
		hysteriaConfig.Masquerade = &masq.Masquerade{
			Handler:  &masqHandlerLogWrapper{H: masqHandler, QUIC: hyConfig.Masquerade.QUIC},
			EnableQUIC: hyConfig.Masquerade.QUIC,
		}
	}

	// CorrectNet
	if hyConfig.CorrectNet != nil {
		cn, err := newCorrectNet(hyConfig.CorrectNet)
		if err != nil {
			return err
		}
		hysteriaConfig.CorrectNet = cn
	}

	// Protean
	pConfig, err := newProtean(hyConfig.Protean)
	if err != nil {
		return err
	}
	hysteriaConfig.ProteanConfig = pConfig

	// Transport
	if hyConfig.Transport != nil {
		var t transport.Transport
		switch hyConfig.Transport.Type {
		case "udp":
			t = transport.NewUDPTransport(hyConfig.Transport.UDP.HopInterval)
		case "wechat":
			t = transport.NewWeChatTransport()
		case "faketcp":
			t = transport.NewFakeTCPTransport()
		default:
			return fmt.Errorf("unsupported transport type: %s", hyConfig.Transport.Type)
		}
		hysteriaConfig.Transport = t
	}

	// Bandwidth
	if hyConfig.Bandwidth != nil {
		hysteriaConfig.Bandwidth = &hysteria.Bandwidth{
			Up:   hyConfig.Bandwidth.Up,
			Down: hyConfig.Bandwidth.Down,
		}
	}

	// Hysteria server
	hyServer, err := hysteria.NewServer(hysteriaConfig)
	if err != nil {
		return err
	}
	defer hyServer.Close()

	// TLS
	// FIX 2: Correctly construct the utls.Config before assigning it.
	// This avoids the type mismatch between server.TLSConfig and utls.Config.
	if hyConfig.TLSConfig != nil {
		var utlsConfig *utls.Config
		if hyConfig.TLSConfig.ACME != nil && hyConfig.TLSConfig.ACME.Domains != "" {
			// CertMagic for automatic certificates
			logger.Info("Using CertMagic for TLS certificates")
			cmCfg, err := newCertmagicConfig(hyConfig.TLSConfig.ACME)
			if err != nil {
				return err
			}
			utlsConfig = newCertmagicTLSConfig(cmCfg)
		} else if hyConfig.TLSConfig.CertFile != "" && hyConfig.TLSConfig.KeyFile != "" {
			// Certificate files for manual setup
			logger.Info("Using certificate files for TLS")
			cert, err := tls.LoadX509KeyPair(hyConfig.TLSConfig.CertFile, hyConfig.TLSConfig.KeyFile)
			if err != nil {
				return fmt.Errorf("failed to load certificate: %v", err)
			}
			utlsConfig = &utls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			}
		} else {
			return errors.New("TLS config not provided")
		}

		// Apply other settings from hyConfig.TLSConfig to the newly created utlsConfig
		if hyConfig.TLSConfig.Insecure {
			utlsConfig.InsecureSkipVerify = true
		}
		if hyConfig.TLSConfig.ServerName != "" {
			utlsConfig.ServerName = hyConfig.TLSConfig.ServerName
		}

		// Assign the fully constructed config to the server instance
		hyServer.TLSConfig = utlsConfig
	}

	// Resolver
	if hyConfig.Resolver != "" {
		r, err := net.ResolveUDPAddr("udp", hyConfig.Resolver)
		if err != nil {
			return fmt.Errorf("failed to resolve custom resolver address: %v", err)
		}
		hyServer.Resolver = r
	}

	// Listen and serve
	addr := net.JoinHostPort(hyConfig.Host, strconv.Itoa(hyConfig.Port))
	logger.Info("server up and running", zap.String("addr", addr))
	return hyServer.Serve(addr)
}

// serverLogger is a simple logger that implements hysteria.Logger
type serverLogger struct{}

func (l *serverLogger) Debug(msg string, fields ...zap.Field) {
	logger.Debug(msg, fields...)
}

func (l *serverLogger) Info(msg string, fields ...zap.Field) {
	logger.Info(msg, fields...)
}

func (l *serverLogger) Warn(msg string, fields ...zap.Field) {
	logger.Warn(msg, fields...)
}

func (l *serverLogger) Error(msg string, fields ...zap.Field) {
	logger.Error(msg, fields...)
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
		zap.String("path", r.URL.Path),
		zap.String("proto", r.Proto),
		zap.String("user-agent", r.UserAgent()),
	)
	m.H.ServeHTTP(w, r)
}
