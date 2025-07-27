package client

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// Common API Path Pool
var commonAPIPaths = []string{
	"/api/v1/auth", "/user/login", "/oauth/token", "/session/create",
	"/api/session", "/auth/v2/login", "/web/auth/verify",
	"/api/user/validate", "/signin", "/accounts/session", "/v2/access", "/api/v3/authenticate",
}

var commonHeaderNames = []string{
	"Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection",
	"Referer", "Origin", "Sec-Fetch-Mode", "DNT", "TE", "Pragma",
	"X-Request-ID", "X-Device-Capability", "X-Client-Telemetry", "X-Custom-Data",
}
var commonHeaderValues = map[string][]string{
	"Accept":          {"*/*", "application/json", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	"Accept-Encoding": {"gzip, deflate, br", "gzip, deflate", "br"},
	"Accept-Language": {"en-US,en;q=0.9", "zh-CN,zh;q=0.8", "en;q=0.5"},
	"Cache-Control":   {"no-cache", "max-age=0"},
	"Connection":      {"keep-alive"},
	"Referer":         {"https://example.com/", "https://google.com/", ""},
	"Origin":          {"https://example.com", "https://google.com"},
	"Sec-Fetch-Mode":  {"cors", "navigate", "same-origin"},
	"DNT":             {"1", "0"},
	"TE":              {"trailers"},
	"Pragma":          {"no-cache"},
	"X-Request-ID":    {""},
	"X-Device-Capability": {""},
	"X-Client-Telemetry": {""},
	"X-Custom-Data":   {""},
}

func pickRandom(s []string) string {
	return s[rand.Intn(len(s))]
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func randomUUID() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", rand.Uint32(), rand.Uint32()>>16, rand.Uint32()>>16, rand.Uint32()>>16, rand.Uint32())
}

// 随机API路径和参数
func randomAPIPathAndQuery() (string, string) {
	path := commonAPIPaths[rand.Intn(len(commonAPIPaths))]
	numParams := rand.Intn(4) + 2 // 2~5
	params := url.Values{}
	for i := 0; i < numParams; i++ {
		key := fmt.Sprintf("p%d_%s", i, randomString(rand.Intn(6)+3))
		val := randomString(rand.Intn(10) + 4)
		params.Add(key, val)
	}
	return path, params.Encode()
}

// 生成混淆认证Header和Body
func buildAuthRequestObfuscatedHeaders(authToken string, rxRate uint64) (http.Header, []byte, string) {
	h := make(http.Header)
	// 1. 主体 Header 必须有 Authorization/Cookie
	h.Set("Authorization", "Bearer "+authToken)
	h.Set("Cookie", fmt.Sprintf("session_id=%s; user_token=%s", randomString(32), randomString(16)))

	// 2. 必须有User-Agent
	ua := fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36 XLESS/%s",
		70+rand.Intn(20), rand.Intn(5000)+1000, rand.Intn(100), randomString(6))
	h.Set("User-Agent", ua)

	// 3. 5~10 个常用 HTTP header，顺序和内容随机
	perm := rand.Perm(len(commonHeaderNames))
	numHeaders := rand.Intn(6) + 5
	for i := 0; i < numHeaders && i < len(commonHeaderNames); i++ {
		name := commonHeaderNames[perm[i]]
		switch name {
		case "X-Request-ID":
			h.Set(name, randomUUID())
		case "X-Device-Capability":
			h.Set(name, fmt.Sprintf(`{"bandwidth":%d}`, rand.Intn(10000000)+10000))
		case "X-Client-Telemetry":
			h.Set(name, fmt.Sprintf(`{"rx_rate":%d,"timestamp":"%d"}`, rxRate, time.Now().Unix()))
		case "X-Custom-Data":
			h.Set(name, randomString(rand.Intn(32)+8))
		default:
			h.Set(name, pickRandom(commonHeaderValues[name]))
		}
	}

	// 4. Body
	type bodyStruct struct {
		Token  string `json:"token"`
		RxRate uint64 `json:"rx_rate"`
	}
	body := bodyStruct{Token: authToken, RxRate: rxRate}
	bodyMap := make(map[string]interface{})
	b, _ := json.Marshal(body)
	json.Unmarshal(b, &bodyMap)
	for i := 0; i < rand.Intn(6)+3; i++ {
		bodyMap[randomString(rand.Intn(8)+4)] = randomString(rand.Intn(24)+8)
	}
	obfBody, _ := json.Marshal(bodyMap)
	h.Set("Content-Type", "application/json")

	return h, obfBody, "application/json"
}
