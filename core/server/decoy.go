package server

import (
	"io"
	"net/http"
	"net/url"
	"time"
)

// DecoyProxy provides a simple reverse proxy to the configured decoy site.
type DecoyProxy struct {
	target *url.URL
	client *http.Client
}

func NewDecoyProxy(target string) *DecoyProxy {
	u, _ := url.Parse(target)
	return &DecoyProxy{
		target: u,
		client: &http.Client{Timeout: 4 * time.Second},
	}
}

// ServeHTTP forwards the given request to the decoy site and writes back the response.
func (dp *DecoyProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Clone the request to send to the decoy.
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.URL.Scheme = dp.target.Scheme
	req.URL.Host = dp.target.Host
	// Remove H3 pseudo-headers, just in case.
	req.Header.Del(":authority")
	req.Header.Del(":method")
	req.Header.Del(":path")

	resp, err := dp.client.Do(req)
	if err != nil {
		w.WriteHeader(502)
		w.Write([]byte("decoy unreachable"))
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
