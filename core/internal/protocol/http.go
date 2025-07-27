package protocol

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	URLHost = "xless"
	// You may ignore this fixed path for auth, since server recognizes dynamic API paths
	URLPath = "/auth"
	// ... unchanged ...
	RequestHeaderAuth        = "xless-Auth"
	ResponseHeaderUDPEnabled = "xless-UDP"
	CommonHeaderCCRX         = "xless-CC-RX"
	CommonHeaderPadding      = "xless-Padding"
	StatusAuthOK             = 233
)

type AuthRequest struct {
	Auth string
	Rx   uint64 // 0 = unknown, client asks server to use bandwidth detection
}

// Parse authentication info from a heavily obfuscated HTTP request according to XLESS SPEC.
func AuthRequestFromObfuscated(r *http.Request) AuthRequest {
	auth := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		auth = strings.TrimPrefix(authHeader, "Bearer ")
	}
	cookieHeader := r.Header.Get("Cookie")
	if strings.Contains(cookieHeader, "session_id=") {
		// Optionally parse session_id from Cookie as a fallback if Authorization is empty
		parts := strings.Split(cookieHeader, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "session_id=") {
				val := strings.TrimPrefix(part, "session_id=")
				val = strings.TrimSpace(val)
				// Use session_id only if auth is still empty
				if auth == "" && val != "" {
					auth = val
				}
				break
			}
		}
	}
	// Default RX rate to 0 (unknown)
	var rx uint64 = 0
	// Try to parse X-Client-Telemetry or X-Device-Capability header as obfuscated RX
	if telemetry := r.Header.Get("X-Client-Telemetry"); telemetry != "" {
		var data map[string]interface{}
		_ = json.Unmarshal([]byte(telemetry), &data)
		if v, ok := data["rx_rate"].(float64); ok && v > 0 {
			rx = uint64(v)
		}
	}
	if rx == 0 {
		if devcap := r.Header.Get("X-Device-Capability"); devcap != "" {
			var data map[string]interface{}
			_ = json.Unmarshal([]byte(devcap), &data)
			if v, ok := data["bandwidth"].(float64); ok && v > 0 {
				rx = uint64(v)
			}
		}
	}
	// Try JSON body (token/rx_rate fields)
	if rx == 0 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		bodyRaw, err := io.ReadAll(r.Body)
		if err == nil && len(bodyRaw) > 0 {
			var body map[string]interface{}
			_ = json.Unmarshal(bodyRaw, &body)
			// Restore body for further reading
			r.Body = io.NopCloser(strings.NewReader(string(bodyRaw)))
			if v, ok := body["rx_rate"].(float64); ok && v > 0 {
				rx = uint64(v)
			}
			if t, ok := body["token"].(string); ok && t != "" && auth == "" {
				auth = t
			}
		}
	}
	return AuthRequest{
		Auth: auth,
		Rx:   rx,
	}
}

// AuthResponse is what server sends to client when authentication is passed.
type AuthResponse struct {
	UDPEnabled bool
	Rx         uint64 // 0 = unlimited
	RxAuto     bool   // true = server asks client to use bandwidth detection
}

func AuthRequestFromHeader(h http.Header) AuthRequest {
	rx, _ := strconv.ParseUint(h.Get(CommonHeaderCCRX), 10, 64)
	return AuthRequest{
		Auth: h.Get(RequestHeaderAuth),
		Rx:   rx,
	}
}

func AuthRequestToHeader(h http.Header, req AuthRequest) {
	h.Set(RequestHeaderAuth, req.Auth)
	h.Set(CommonHeaderCCRX, strconv.FormatUint(req.Rx, 10))
	h.Set(CommonHeaderPadding, authRequestPadding.String())
}

func AuthResponseFromHeader(h http.Header) AuthResponse {
	resp := AuthResponse{}
	resp.UDPEnabled, _ = strconv.ParseBool(h.Get(ResponseHeaderUDPEnabled))
	rxStr := h.Get(CommonHeaderCCRX)
	if rxStr == "auto" {
		// Special case for server requesting client to use bandwidth detection
		resp.RxAuto = true
	} else {
		resp.Rx, _ = strconv.ParseUint(rxStr, 10, 64)
	}
	return resp
}

func AuthResponseToHeader(h http.Header, resp AuthResponse) {
	h.Set(ResponseHeaderUDPEnabled, strconv.FormatBool(resp.UDPEnabled))
	if resp.RxAuto {
		h.Set(CommonHeaderCCRX, "auto")
	} else {
		h.Set(CommonHeaderCCRX, strconv.FormatUint(resp.Rx, 10))
	}
	h.Set(CommonHeaderPadding, authResponsePadding.String())
}
