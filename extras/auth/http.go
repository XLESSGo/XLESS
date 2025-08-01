package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/XLESSGo/XLESS/core/server"
)

const (
	httpAuthTimeout = 10 * time.Second
)

var _ server.Authenticator = &HTTPAuthenticator{}

var errInvalidStatusCode = errors.New("invalid status code")

type HTTPAuthenticator struct {
	Client *http.Client
	URL    string
}

func NewHTTPAuthenticator(url string, insecure bool) *HTTPAuthenticator {
	// 创建标准的 crypto/tls.Config 实例
	stdTLSClientConfig := &tls.Config{
		InsecureSkipVerify: insecure,
		// 客户端通常不需要 Certificates 或 GetCertificate
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = stdTLSClientConfig // 使用转换后的标准 TLS 配置

	return &HTTPAuthenticator{
		Client: &http.Client{
			Transport: tr,
			Timeout:   httpAuthTimeout,
		},
		URL: url,
	}
}

type httpAuthRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   uint64 `json:"tx"`
}

type httpAuthResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

func (a *HTTPAuthenticator) post(req *httpAuthRequest) (*httpAuthResponse, error) {
	bs, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := a.Client.Post(a.URL, "application/json", bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errInvalidStatusCode
	}
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var authResp httpAuthResponse
	err = json.Unmarshal(respData, &authResp)
	if err != nil {
		return nil, err
	}
	return &authResp, nil
}

func (a *HTTPAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	req := &httpAuthRequest{
		Addr: addr.String(),
		Auth: auth,
		Tx:   tx,
	}
	resp, err := a.post(req)
	if err != nil {
		return false, ""
	}
	return resp.OK, resp.ID
}
