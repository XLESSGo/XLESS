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
			MinVersion:         s.TLSConfig.MinVersion,
			MaxVersion:         s.TLSConfig.MaxVersion,
			CipherSuites:       s.TLSConfig.CipherSuites,
			// ... 其他你需要从 utls.Config 复制到 crypto/tls.Config 的字段
		}

		// 转换 Certificates: []utls.Certificate -> []crypto/tls.Certificate
		if len(s.TLSConfig.Certificates) > 0 {
			stdTLSConfig.Certificates = make([]tls.Certificate, len(s.TLSConfig.Certificates))
			for i, cert := range s.TLSConfig.Certificates {
				stdTLSConfig.Certificates[i] = tls.Certificate(cert) // 直接转换
			}
		}

		// 转换 GetCertificate 函数: func(*utls.ClientHelloInfo) -> func(*crypto/tls.ClientHelloInfo)
		if s.TLSConfig.GetCertificate != nil {
			stdTLSConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// 1. 将 crypto/tls.ClientHelloInfo 转换为 utls.ClientHelloInfo
				// 需要手动遍历转换切片，以避免直接类型转换的限制
				utlsSupportedCurves := make([]utls.CurveID, len(info.SupportedCurves))
				for i, c := range info.SupportedCurves {
					utlsSupportedCurves[i] = utls.CurveID(c)
				}

				// utls.ClientHelloInfo 的 SupportedPoints 通常是 []uint8，
				// 而 crypto/tls.ClientHelloInfo.SupportedPoints 是 []tls.CurveP256 (uint8 的别名)
				// 这里需要将 []tls.CurveP256 转换为 []uint8
				utlsSupportedPoints := make([]uint8, len(info.SupportedPoints))
				for i, p := range info.SupportedPoints {
					utlsSupportedPoints[i] = uint8(p) // 将 tls.CurveP256 (uint8) 转换为 uint8
				}

				utlsSignatureSchemes := make([]utls.SignatureScheme, len(info.SignatureSchemes))
				for i, s := range info.SignatureSchemes {
					utlsSignatureSchemes[i] = utls.SignatureScheme(s)
				}

				utlsInfo := &utls.ClientHelloInfo{
					CipherSuites:      info.CipherSuites,
					ServerName:        info.ServerName,
					SupportedCurves:   utlsSupportedCurves,
					SupportedPoints:   utlsSupportedPoints, // 使用转换后的 []uint8
					SignatureSchemes:  utlsSignatureSchemes,
					SupportedVersions: info.SupportedVersions,
					Conn:              info.Conn,
				}

				// 2. 调用原始的 utls.GetCertificate
				utlsCert, err := s.TLSConfig.GetCertificate(utlsInfo)
				if err != nil {
					return nil, err
				}
				if utlsCert == nil {
					return nil, nil // 重要：如果原始函数返回nil证书，也返回nil
				}

				// 3. 将返回的 *utls.Certificate 转换为 *crypto/tls.Certificate
				stdCert := tls.Certificate(*utlsCert) // 先解引用得到结构体，再转换
				return &stdCert, nil                  // 返回转换后的结构体的指针
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
