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
	var stdTLSConfig *tls.Config
	if s.TLSConfig != nil {
		stdTLSConfig = &tls.Config{
			InsecureSkipVerify: s.TLSConfig.InsecureSkipVerify,
			ServerName:         s.TLSConfig.ServerName,
			MinVersion:         s.TLSConfig.MinVersion,
			MaxVersion:         s.TLSConfig.MaxVersion,
			CipherSuites:       s.TLSConfig.CipherSuites,
			// Add other fields you might use from utls.Config that are also in crypto/tls.Config
		}

		// --- START FIX for Error 1: cannot convert cert (variable of struct type "github.com/refraction-networking/utls".Certificate) to type "crypto/tls".Certificate ---
		if len(s.TLSConfig.Certificates) > 0 {
			stdTLSConfig.Certificates = make([]tls.Certificate, len(s.TLSConfig.Certificates))
			for i, utlsCertEntry := range s.TLSConfig.Certificates {
				stdTLSConfig.Certificates[i] = tls.Certificate{
					Certificate: utlsCertEntry.Certificate, // []byte
					PrivateKey:  utlsCertEntry.PrivateKey,  // crypto.Signer
					Leaf:        utlsCertEntry.Leaf,        // *x509.Certificate
					// Copy other relevant fields if they exist and are exported in both structs
					// For most basic use cases, these three are sufficient.
				}
			}
		}
		// --- END FIX ---

		if s.TLSConfig.GetCertificate != nil {
			stdTLSConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				utlsSupportedCurves := make([]utls.CurveID, len(info.SupportedCurves))
				for i, c := range info.SupportedCurves {
					utlsSupportedCurves[i] = utls.CurveID(c)
				}

				utlsSupportedPoints := make([]uint8, len(info.SupportedPoints))
				for i, p := range info.SupportedPoints {
					utlsSupportedPoints[i] = uint8(p)
				}

				utlsSignatureSchemes := make([]utls.SignatureScheme, len(info.SignatureSchemes))
				for i, s := range info.SignatureSchemes {
					utlsSignatureSchemes[i] = utls.SignatureScheme(s)
				}

				utlsInfo := &utls.ClientHelloInfo{
					CipherSuites:      info.CipherSuites,
					ServerName:        info.ServerName,
					SupportedCurves:   utlsSupportedCurves,
					SupportedPoints:   utlsSupportedPoints,
					SignatureSchemes:  utlsSignatureSchemes,
					SupportedVersions: info.SupportedVersions,
					Conn:              info.Conn,
				}

				utlsCert, err := s.TLSConfig.GetCertificate(utlsInfo)
				if err != nil {
					return nil, err
				}

				// --- START FIX for Error 2: cannot convert *utlsCert (...) to type "crypto/tls".Certificate ---
				if utlsCert == nil {
					return nil, nil
				}
				stdCert := tls.Certificate{
					Certificate: utlsCert.Certificate,
					PrivateKey:  utlsCert.PrivateKey,
					Leaf:        utlsCert.Leaf,
					// Copy other relevant fields if they exist and are exported
				}
				return &stdCert, nil
				// --- END FIX ---
			}
		}
	}

	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
		}),
		TLSConfig: stdTLSConfig,
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
