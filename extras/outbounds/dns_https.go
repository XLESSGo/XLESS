package outbounds

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns" // For building and parsing DNS messages
	// Import the DoH client package from XLESSGo.
	// Replace "github.com/XLESSGo/XLESS/extras/outbounds/doh" with the actual path if different.
	doh "github.com/XLESSGo/XLESS/extras/outbounds/doh"
	"github.com/m13253/dns-over-https/v2/doh-client/selector" // Required by XLESSGo's doh.Client
)

// dohResolver is a PluggableOutbound DNS resolver that resolves hostnames
// using the user-provided DNS-over-HTTPS server from the XLESSGo project.
type dohResolver struct {
	Client *doh.Client // The DoH client instance from github.com/XLESSGo/XLESS/extra/outbounds/doh
	Next   PluggableOutbound
}

// NewDoHResolver creates a new dohResolver instance.
// host: The full URL of the DoH service (e.g., "https://dns.google/dns-query").
// timeout: Timeout for DNS queries.
// sni: Server Name Indication for TLS connections.
// insecure: If true, skips TLS certificate verification (ONLY for testing, NOT recommended for production).
// next: The next PluggableOutbound in the chain.
func NewDoHResolver(host string, timeout time.Duration, sni string, insecure bool, next PluggableOutbound) PluggableOutbound {
	// Create a minimal doh.Config struct to initialize the XLESSGo's doh.Client.
	config := &doh.Config{
		Upstream: doh.UpstreamSectionConfig{
			UpstreamSelector: "random", // Using random selector for simplicity with a single upstream
			UpstreamIETF: []doh.UpstreamConfig{ // Assuming the host is an IETF-style DoH endpoint
				{
					URL:    host,
					Weight: 100, // Default weight for a single upstream
				},
			},
		},
		Other: doh.OtherConfig{
			InsecureTLSSkipVerify: insecure,
			Timeout:               timeoutOrDefault(timeout), // Use the provided timeout
		},
	}

	// Create a RandomSelector as required by doh.NewClient's signature.
	randomSelector := selector.NewRandomSelector()
	// Add the upstream to the selector. Assuming IETF for generic DoH.
	err := randomSelector.Add(host, selector.IETF)
	if err != nil {
		panic("Failed to add upstream to selector: " + err.Error())
	}

	// Initialize the XLESSGo's doh.Client with the created config and selector.
	// FIXED: Passing 'randomSelector' to match doh.NewClient's expected signature.
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
		// If the host is already an IP address, no resolution is needed.
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
		// Set the DNS question for A record, converting hostname to FQDN.
		m.SetQuestion(dns.Fqdn(reqAddr.Host), dns.TypeA)
		m.RecursionDesired = true // Request recursive query

		// FIXED: r.Client.Exchange is undefined.
		// NOTE: The 'Exchange' method is NOT part of the public API of
		// github.com/XLESSGo/XLESS/extras/outbounds/doh.Client in its original form.
		// For this code to compile and be "actual usable", you MUST add an 'Exchange' method
		// to the 'doh.Client' type in your forked 'github.com/XLESSGo/XLESS/extras/outbounds/doh/client.go' file.
		// Example signature for the required method:
		// func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
		resp, err := r.Client.Exchange(context.Background(), m)

		var ip net.IP
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			// Iterate through the Answer section of the response to find A records.
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					ip = a.A // Get the net.IP directly
					break    // Take the first A record found
				}
			}
		}
		ch4 <- lookupResult{ip, err}
	}()

	// Asynchronously query for AAAA records (IPv6).
	go func() {
		m := new(dns.Msg)
		// Set the DNS question for AAAA record, converting hostname to FQDN.
		m.SetQuestion(dns.Fqdn(reqAddr.Host), dns.TypeAAAA)
		m.RecursionDesired = true // Request recursive query

		// FIXED: r.Client.Exchange is undefined. (Same issue as above)
		// See the NOTE above for the A record query.
		resp, err := r.Client.Exchange(context.Background(), m)

		var ip net.IP
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			// Iterate through the Answer section of the response to find AAAA records.
			for _, ans := range resp.Answer {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					ip = aaaa.AAAA // Get the net.IP directly
					break          // Take the first AAAA record found
				}
			}
		}
		ch6 <- lookupResult{ip, err}
	}()

	// Wait for both A and AAAA query results.
	result4, result6 := <-ch4, <-ch6
	reqAddr.ResolveInfo = &ResolveInfo{
		IPv4: result4.ip,
		IPv6: result6.ip,
	}
	// If IPv4 query had an error, set it; otherwise, if IPv6 query had an error, set it.
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
