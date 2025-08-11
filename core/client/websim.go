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

// sendAuxiliaryRequests picks resources to request with a random delay.
// It will request `count` resources if configured and there are at least 4 available.
// Otherwise, it falls back to the default behavior of requesting 2-4 resources.
func sendAuxiliaryRequests(client *http.Client, resources []string, count int) {
	if len(resources) == 0 {
		return
	}

	var num int
	if count > 0 && len(resources) >= 4 {
		// 使用配置的个数，但不超过可用资源总数
		if count < len(resources) {
			num = count
		} else {
			num = len(resources)
		}
	} else {
		// 使用默认机制：随机 2-4 个
		num = rand.Intn(3) + 2
		if len(resources) < num {
			num = len(resources)
		}
	}
	
	for i := 0; i < num; i++ {
		_, _ = client.Get(resources[i])
		time.Sleep(time.Duration(300+rand.Intn(900)) * time.Millisecond)
	}
}
