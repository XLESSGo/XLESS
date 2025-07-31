package outbounds

import (
	"context" // 用于 dohClient.Client.Exchange 方法
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns" // 用于构建和解析 DNS 消息
	dohClient "github.com/m13253/dns-over-https/v2/doh-client" // 导入新的 DoH 客户端库，并使用别名避免冲突
)

// dohResolver 是一个 PluggableOutbound DNS 解析器，
// 它使用用户提供的 DNS-over-HTTPS 服务器解析主机名。
type dohResolver struct {
	Client *dohClient.Client // 更改为新的客户端类型
	Next   PluggableOutbound
}

// NewDoHResolver 创建一个新的 dohResolver 实例。
// host 参数应为完整的 DoH 服务 URL (例如: "https://dns.google/dns-query")。
func NewDoHResolver(host string, timeout time.Duration, sni string, insecure bool, next PluggableOutbound) PluggableOutbound {
	// 创建标准的 crypto/tls.Config 实例
	stdTLSClientConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		// 对于客户端，通常不需要 Certificates 或 GetCertificate
	}

	// m13253/dns-over-https/doh-client.NewClient 期望一个 Config 结构体
	// 它会在内部创建并管理 http.Client
	config := &dohClient.Config{
		UpstreamURL:     host, // 这是完整的 DoH URL
		TLSClientConfig: stdTLSClientConfig,
		Timeout:         timeoutOrDefault(timeout),
		// NoECS 和 Verbose 字段可以根据需要设置，默认为 false
	}

	client, err := dohClient.NewClient(config)
	if err != nil {
		// 在客户端创建失败时，根据您的应用程序错误处理策略进行处理。
		// 这里选择 panic 以简化示例，但在实际应用中应返回错误或更优雅地处理。
		panic(err)
	}

	return &dohResolver{
		Client: client, // 使用新的客户端实例
		Next:   next,
	}
}

// resolve 方法执行 DNS 解析。
func (r *dohResolver) resolve(reqAddr *AddrEx) {
	if tryParseIP(reqAddr) {
		// 如果主机已经是 IP 地址，则无需解析。
		return
	}

	type lookupResult struct {
		ip  net.IP
		err error
	}
	ch4, ch6 := make(chan lookupResult, 1), make(chan lookupResult, 1)

	// 异步查询 A 记录
	go func() {
		m := new(dns.Msg)
		// 设置 DNS 查询问题，将主机名转换为完全限定域名 (FQDN)
		m.SetQuestion(dns.Fqdn(reqAddr.Host), dns.TypeA)
		m.RecursionDesired = true // 请求递归查询

		// 使用新的 DoH 客户端执行 DNS 消息交换
		resp, err := r.Client.Exchange(context.Background(), m)
		var ip net.IP
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			// 遍历响应中的 Answer 部分，查找 A 记录
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					ip = a.A // 直接获取 net.IP 类型
					break    // 只获取第一个 A 记录
				}
			}
		}
		ch4 <- lookupResult{ip, err}
	}()

	// 异步查询 AAAA 记录
	go func() {
		m := new(dns.Msg)
		// 设置 DNS 查询问题，将主机名转换为完全限定域名 (FQDN)
		m.SetQuestion(dns.Fqdn(reqAddr.Host), dns.TypeAAAA)
		m.RecursionDesired = true // 请求递归查询

		// 使用新的 DoH 客户端执行 DNS 消息交换
		resp, err := r.Client.Exchange(context.Background(), m)
		var ip net.IP
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			// 遍历响应中的 Answer 部分，查找 AAAA 记录
			for _, ans := range resp.Answer {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					ip = aaaa.AAAA // 直接获取 net.IP 类型
					break          // 只获取第一个 AAAA 记录
				}
			}
		}
		ch6 <- lookupResult{ip, err}
	}()

	// 等待 A 和 AAAA 记录的查询结果
	result4, result6 := <-ch4, <-ch6
	reqAddr.ResolveInfo = &ResolveInfo{
		IPv4: result4.ip,
		IPv6: result6.ip,
	}
	// 如果 IPv4 查询有错误，则设置错误信息；否则如果 IPv6 查询有错误，则设置错误信息
	if result4.err != nil {
		reqAddr.ResolveInfo.Err = result4.err
	} else if result6.err != nil {
		reqAddr.ResolveInfo.Err = result6.err
	}
}

// TCP 方法实现 PluggableOutbound 接口的 TCP 部分。
func (r *dohResolver) TCP(reqAddr *AddrEx) (net.Conn, error) {
	r.resolve(reqAddr)
	return r.Next.TCP(reqAddr)
}

// UDP 方法实现 PluggableOutbound 接口的 UDP 部分。
func (r *dohResolver) UDP(reqAddr *AddrEx) (UDPConn, error) {
	r.resolve(reqAddr)
	return r.Next.UDP(reqAddr)
}

// timeoutOrDefault 是一个辅助函数，用于提供默认超时时间。
// 实际的实现应根据您的项目需求进行调整。
func timeoutOrDefault(d time.Duration) time.Duration {
	if d == 0 {
		return 5 * time.Second // 默认超时时间
	}
	return d
}

// tryParseIP 是一个辅助函数，用于检查主机是否已经是 IP 地址。
// 实际的实现应根据您的项目需求进行调整。
func tryParseIP(reqAddr *AddrEx) bool {
	return net.ParseIP(reqAddr.Host) != nil
}

