package doh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/miekg/dns"
	"github.com/m13253/dns-over-https/v2/doh-client/selector" // Required for selector.Upstream type
)

// Get returns an upstream from the client's internal selector.
// It uses the 'selector' field of the Client struct.
func (c *Client) Get() *selector.Upstream {
	if c.selector == nil { // Corrected field name from c.s to c.selector
		// This indicates the selector was not properly initialized in NewClient.
		// In a production scenario, you might want to return a specific error.
		return nil
	}
	return c.selector.Get() // Corrected to call the Get method on the selector
}

// Exchange performs a DNS-over-HTTPS query using the client's internal HTTP client and selector.
// It uses the 'httpClient' field of the Client struct.
func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	upstream := c.Get()
	if upstream == nil {
		return nil, fmt.Errorf("no upstream available from selector")
	}

	msgBytes, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	reqURL := upstream.URL

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(msgBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", upstream.RequestType)
	req.Header.Set("Accept", upstream.RequestType)

	if c.httpClient == nil { // Corrected field name from c.client to c.httpClient
		// This indicates the http.Client was not properly initialized in NewClient.
		return nil, fmt.Errorf("internal HTTP client is not initialized")
	}
	resp, err := c.httpClient.Do(req) // Corrected field name from c.client to c.httpClient
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	responseMsg := new(dns.Msg)
	err = responseMsg.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return responseMsg, nil
}
