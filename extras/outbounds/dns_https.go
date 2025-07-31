package outbounds

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns" // For building and parsing DNS messages
	doh "github.com/XLESSGo/XLESS/extras/outbounds/doh" // XLESSGo's DoH package
	upstream_config "github.com/m13253/dns-over-https/v2/doh-client/config" // Import the correct config package
	"github.com/m13253/dns-over-https/v2/doh-client/selector" // Selector used by XLESSGo's doh.Client
)

// dohResolver is a PluggableOutbound DNS resolver that resolves hostnames
// using the user-provided DNS-over-HTTPS server from the XLESSGo project.
type dohResolver struct {
	Client *doh.Client // The DoH client instance from github.com/XLESSGo/XLESS/extra/outbounds/doh
	Next   PluggableOutbound
}

// NewDoHResolver creates a new dohResolver instance.
// host: The full URL of the DoH service.
// timeout: Timeout for DNS queries.
// sni: Server Name Indication for TLS connections.
// insecure: If true, skips TLS certificate verification (NOT recommended for production).
// next: The next PluggableOutbound in the chain.
func NewDoHResolver(host string, timeout time.Duration, sni string, insecure bool, next PluggableOutbound) PluggableOutbound {
	// Create config for XLESSGo's doh.Client, using the correct upstream_config.Config type.
	config := &upstream_config.Config{ // FIXED: Changed type from *doh.Config to *upstream_config.Config
		Upstream: upstream_config.UpstreamSectionConfig{
			UpstreamSelector: "random",
			UpstreamIETF: []upstream_config.UpstreamConfig{
				{URL: host, Weight: 100},
			},
		},
		Other: upstream_config.OtherConfig{
			InsecureTLSSkipVerify: insecure,
			Timeout:               int(timeoutOrDefault(timeout).Seconds()), // FIXED: Convert time.Duration to int seconds
		},
	}

	// Create a selector instance as required by doh.NewClient's signature.
	randomSelector := selector.NewRandomSelector()
	// Add the upstream to the selector. Assuming IETF type for generic DoH.
	err := randomSelector.Add(host, selector.IETF)
	if err != nil {
		panic("Failed to add upstream to selector: " + err.Error())
	}

	// Initialize XLESSGo's doh.Client.
	client, err := doh.NewClient(config, randomSelector)
	if err != nil {
		panic("Failed to create DoH client: " + err.Error())
	}

	return &dohResolver{
		Client: client,
		Next:   next,
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

		// r.Client.Exchange is now defined in doh/doh.go.
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

		// r.Client.Exchange is now defined in doh/doh.go.
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

