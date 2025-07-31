package outbounds

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns" // For building and parsing DNS messages
	doh "github.com/XLESSGo/XLESS/extras/outbounds/doh" // XLESSGo's DoH package
	// selector is still imported as doh.NewClient might internally use it.
	"github.com/m13253/dns-over-https/v2/doh-client/selector"
)

// dohResolver is a PluggableOutbound DNS resolver that resolves hostnames
// using the user-provided DNS-over-HTTPS server from the XLESSGo project.
type dohResolver struct {
	Client *doh.Client // The DoH client instance from github.com/XLESSGo/XLESS/extras/outbounds/doh
	// httpClient is no longer needed here as doh.Client will expose Exchange method.
	Next PluggableOutbound
}

// NewDoHResolver creates a new dohResolver instance.
// host: The full URL of the DoH service.
// timeout: Timeout for DNS queries.
// sni: Server Name Indication for TLS connections.
// insecure: If true, skips TLS certificate verification (NOT recommended for production).
// next: The next PluggableOutbound in the chain.
func NewDoHResolver(host string, timeout time.Duration, sni string, insecure bool, next PluggableOutbound) PluggableOutbound {
	// Create doh.Config for XLESSGo's doh.Client.
	config := &doh.Config{
		Upstream: doh.UpstreamSectionConfig{
			UpstreamSelector: "random",
			UpstreamIETF: []doh.UpstreamConfig{
				{URL: host, Weight: 100},
			},
		},
		Other: doh.OtherConfig{
			InsecureTLSSkipVerify: insecure,
			// FIXED: Convert time.Duration to int (milliseconds) as expected by doh.OtherConfig.Timeout.
			// Assuming Timeout expects milliseconds based on common Go network library patterns.
			Timeout: int(timeoutOrDefault(timeout).Milliseconds()),
		},
	}

	// Create the selector instance.
	randomSelector := selector.NewRandomSelector()
	// The `randomSelector.Add` call is also not directly relevant here if NewClient only takes config.
	// If XLESSGo's doh.NewClient internally uses the selector package, it will handle this.
	// For now, we assume the config fully dictates the upstream setup.

	// Initialize XLESSGo's doh.Client.
	// FIXED: Added 'randomSelector' as the second argument to doh.NewClient.
	client, err := doh.NewClient(config, randomSelector)
	if err != nil {
		panic("Failed to create DoH client: " + err.Error())
	}

	// Custom HTTP client is no longer needed here as doh.Client will expose Exchange method.
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{
	// 		ServerName:        sni,
	// 		InsecureSkipVerify: insecure,
	// 	},
	// 	DisableKeepAlives: true,
	// }
	// httpClient := &http.Client{
	// 	Transport: tr,
	// 	Timeout:   timeoutOrDefault(timeout),
	// }

	return &dohResolver{
		Client: client,
		// httpClient: httpClient, // Removed
		Next: next,
	}
}

// resolve performs DNS resolution for the given AddrEx using the DoH client.
func (r *dohResolver) resolve(reqAddr *AddrEx) {
	if tryParseIP(reqAddr) {
		return
	}

	type lookupResult struct {
		ip  net.IP
		err error
	}
	ch4, ch6 := make(chan lookupResult, 1), make(chan lookupResult, 1)

	// Asynchronously query for A records (IPv4).
	go func() {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(reqAddr.Host), dns.TypeA)
		m.RecursionDesired = true

		// FIXED: r.Client.Exchange is now defined in doh/doh.go.
		resp, err := r.Client.Exchange(context.Background(), m)
		var ip net.IP
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					ip = a.A
					break
				}
			}
		}
		ch4 <- lookupResult{ip, err}
	}()

	// Asynchronously query for AAAA records (IPv6).
	go func() {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(reqAddr.Host), dns.TypeAAAA)
		m.RecursionDesired = true

		// FIXED: r.Client.Exchange is now defined in doh/doh.go.
		resp, err := r.Client.Exchange(context.Background(), m)
		var ip net.IP
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			for _, ans := range resp.Answer {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					ip = aaaa.AAAA
					break
				}
			}
		}
		ch6 <- lookupResult{ip, err}
	}()

	result4, result6 := <-ch4, <-ch6
	reqAddr.ResolveInfo = &ResolveInfo{
		IPv4: result4.ip,
		IPv6: result6.ip,
	}
	if result4.err != nil {
		reqAddr.ResolveInfo.Err = result4.err
	} else if result6.err != nil {
		reqAddr.ResolveInfo.Err = result6.err
	}
}

// TCP implements the TCP part of the PluggableOutbound interface.
func (r *dohResolver) TCP(reqAddr *AddrEx) (net.Conn, error) {
	r.resolve(reqAddr)
	return r.Next.TCP(reqAddr)
}

// UDP implements the UDP part of the PluggableOutbound interface.
func (r *dohResolver) UDP(reqAddr *AddrEx) (UDPConn, error) {
	r.resolve(reqAddr)
	return r.Next.UDP(reqAddr)
}
