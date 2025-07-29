package masq

import (
	"bufio"
	"crypto/tls"
	utls "github.com/refraction-networking/utls"
	"fmt"
	"net"
	"net/http"

	"github.com/XLESSGo/XLESS/extras/correctnet"
)

// MasqTCPServer covers the TCP parts of a standard web server (TCP based HTTP/HTTPS).
// We provide this as an option for masquerading, as some may consider a server
// "suspicious" if it only serves the QUIC protocol and not standard HTTP/HTTPS.
type MasqTCPServer struct {
	QUICPort   int
	HTTPSPort  int
	Handler    http.Handler
	TLSConfig  *utls.Config
	ForceHTTPS bool // Always 301 redirect from HTTP to HTTPS
}

func (s *MasqTCPServer) ListenAndServeHTTP(addr string) error {
	return correctnet.HTTPListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ForceHTTPS {
			if s.HTTPSPort == 0 || s.HTTPSPort == 443 {
				// Omit port if it's the default
				http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			} else {
				http.Redirect(w, r, fmt.Sprintf("https://%s:%d%s", r.Host, s.HTTPSPort, r.RequestURI), http.StatusMovedPermanently)
			}
			return
		}
		s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
	}))
}

func (s *MasqTCPServer) ListenAndServeHTTPS(addr string) error {
	// 转换 utls.Config 为 crypto/tls.Config
	var stdTLSConfig *tls.Config
	if s.TLSConfig != nil {
		stdTLSConfig = &tls.Config{
			InsecureSkipVerify: s.TLSConfig.InsecureSkipVerify,
			ServerName:         s.TLSConfig.ServerName,
			// Add other fields you might use from utls.Config like MaxVersion, MinVersion, CipherSuites etc.
			// Example for Certificates:
			Certificates: make([]tls.Certificate, len(s.TLSConfig.Certificates)),
		}
		for i, cert := range s.TLSConfig.Certificates {
			stdTLSConfig.Certificates[i] = tls.Certificate(cert) // 直接转换
		}

		// 转换 GetCertificate 函数 - 这是最复杂的部分
		if s.TLSConfig.GetCertificate != nil {
			stdTLSConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// 1. 将 crypto/tls.ClientHelloInfo 转换为 utls.ClientHelloInfo
				utlsInfo := &utls.ClientHelloInfo{
					CipherSuites:      info.CipherSuites,
					ServerName:        info.ServerName,
					SupportedCurves:   []utls.CurveID(info.SupportedCurves),
					SupportedPoints:   []utls.CurveP256(info.SupportedPoints), // or []utls.CurveP256(info.SupportedPoints)
					SignatureSchemes:  []utls.SignatureScheme(info.SignatureSchemes),
					SupportedVersions: info.SupportedVersions,
					Conn:              info.Conn,
				}

				// 2. 调用原始的 utls.GetCertificate
				utlsCert, err := s.TLSConfig.GetCertificate(utlsInfo)
				if err != nil {
					return nil, err
				}
				if utlsCert == nil {
					return nil, nil
				}

				// 3. 将返回的 *utls.Certificate 转换为 *crypto/tls.Certificate
				stdCert := tls.Certificate(*utlsCert)
				return &stdCert, nil
			}
		}
	}

	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
		}),
		TLSConfig: stdTLSConfig, // 使用转换后的标准 TLS 配置
	}
	listener, err := correctnet.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return server.ServeTLS(listener, "", "")
}

var _ http.ResponseWriter = (*altSvcHijackResponseWriter)(nil)

// altSvcHijackResponseWriter makes sure that the Alt-Svc's port
// is always set with our own value, no matter what the handler sets.
type altSvcHijackResponseWriter struct {
	Port int
	http.ResponseWriter
}

func (w *altSvcHijackResponseWriter) WriteHeader(statusCode int) {
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, w.Port))
	w.ResponseWriter.WriteHeader(statusCode)
}

var _ http.Hijacker = (*altSvcHijackResponseWriterHijacker)(nil)

// altSvcHijackResponseWriterHijacker is a wrapper around altSvcHijackResponseWriter
// that also implements http.Hijacker. This is needed for WebSocket support.
type altSvcHijackResponseWriterHijacker struct {
	altSvcHijackResponseWriter
}

func (w *altSvcHijackResponseWriterHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

func newAltSvcHijackResponseWriter(w http.ResponseWriter, port int) http.ResponseWriter {
	if _, ok := w.(http.Hijacker); ok {
		return &altSvcHijackResponseWriterHijacker{
			altSvcHijackResponseWriter: altSvcHijackResponseWriter{
				Port:           port,
				ResponseWriter: w,
			},
		}
	}
	return &altSvcHijackResponseWriter{
		Port:           port,
		ResponseWriter: w,
	}
}
