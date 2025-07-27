package client

import (
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Regular expression to extract src/href attributes from HTML.
var htmlLinkRegex = regexp.MustCompile(`(?:src|href)=["']([^"']+)["']`)

// SimulateWebBrowse requests /index.html from the decoy site,
// parses all linked resources (src/href), and returns a list of absolute URLs (in order).
// If a link is a relative path (starts with /), it will be joined with decoyBaseURL.
func SimulateWebBrowse(client *http.Client, decoyBaseURL string) ([]string, error) {
	indexURL := decoyBaseURL + "/index.html"
	resp, err := client.Get(indexURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	links := htmlLinkRegex.FindAllStringSubmatch(string(body), -1)
	var resources []string
	for _, l := range links {
		link := l[1]
		if strings.HasPrefix(link, "/") {
			resources = append(resources, decoyBaseURL+link)
		} else if strings.HasPrefix(link, "http") {
			resources = append(resources, link)
		}
	}
	return resources, nil
}

// sendAuxiliaryRequests picks 2-4 resources (or all if not enough links), in order,
// and makes GET requests to each with a random delay between 300ms and 1200ms.
// If there are no resources, this function returns immediately.
func sendAuxiliaryRequests(client *http.Client, resources []string) {
	if len(resources) == 0 {
		return
	}
	// Pick 2-4 resources in order (not shuffled). If not enough, use all.
	num := rand.Intn(3) + 2 // 2~4
	if len(resources) < num {
		num = len(resources)
	}
	for i := 0; i < num; i++ {
		_, _ = client.Get(resources[i])
		time.Sleep(time.Duration(300+rand.Intn(900)) * time.Millisecond)
	}
}
