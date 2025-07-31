package acl

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time" // GCache可能需要time包处理过期时间

	"github.com/XLESSGo/XLESS/extras/outbounds/acl/v2geo"

	"github.com/bluele/gcache" // 切换到 gcache 库
)

type Protocol int

const (
	ProtocolBoth Protocol = iota
	ProtocolTCP
	ProtocolUDP
)

type Outbound interface {
	any
}

type HostInfo struct {
	Name string
	IPv4 net.IP
	IPv6 net.IP
}

func (h HostInfo) String() string {
	return fmt.Sprintf("%s|%s|%s", h.Name, h.IPv4, h.IPv6)
}

type CompiledRuleSet[O Outbound] interface {
	Match(host HostInfo, proto Protocol, port uint16) (O, net.IP)
}

type compiledRule[O Outbound] struct {
	Outbound      O
	HostMatcher   hostMatcher
	Protocol      Protocol
	StartPort     uint16
	EndPort       uint16
	HijackAddress net.IP
}

func (r *compiledRule[O]) Match(host HostInfo, proto Protocol, port uint16) bool {
	if r.Protocol != ProtocolBoth && r.Protocol != proto {
		return false
	}
	if r.StartPort != 0 && (port < r.StartPort || port > r.EndPort) {
		return false
	}
	return r.HostMatcher.Match(host)
}

type matchResult[O Outbound] struct {
	Outbound      O
	HijackAddress net.IP
}

type compiledRuleSetImpl[O Outbound] struct {
	Rules []compiledRule[O]
	// GCache 是非泛型的，所以我们需要使用 interface{} 作为键和值
	Cache gcache.Cache
}

func (s *compiledRuleSetImpl[O]) Match(host HostInfo, proto Protocol, port uint16) (O, net.IP) {
	host.Name = strings.ToLower(host.Name) // Normalize host name to lower case
	key := host.String()

	// GCache.Get 返回 (interface{}, error)
	// 如果 key 不存在或者过期，会返回 ErrKeyNotFound
	cachedResult, err := s.Cache.Get(key)
	if err == nil {
		// 类型断言，如果成功则返回缓存结果
		if result, ok := cachedResult.(matchResult[O]); ok {
			return result.Outbound, result.HijackAddress
		}
	}

	for _, rule := range s.Rules {
		if rule.Match(host, proto, port) {
			result := matchResult[O]{rule.Outbound, rule.HijackAddress}
			// 使用 Set 方法设置缓存，对于 ACL 规则，通常不需要过期时间
			s.Cache.Set(key, result)
			return result.Outbound, result.HijackAddress
		}
	}
	// 没有匹配到规则，也缓存结果，避免重复查找
	var zero O
	s.Cache.Set(key, matchResult[O]{zero, nil})
	return zero, nil
}

type CompilationError struct {
	LineNum int
	Message string
}

func (e *CompilationError) Error() string {
	return fmt.Sprintf("error at line %d: %s", e.LineNum, e.Message)
}

type GeoLoader interface {
	LoadGeoIP() (map[string]*v2geo.GeoIP, error)
	LoadGeoSite() (map[string]*v2geo.GeoSite, error)
}

// Compile compiles TextRules into a CompiledRuleSet.
// Names in the outbounds map MUST be in all lower case.
// We want on-demand loading of GeoIP/GeoSite databases, so instead of passing the
// databases directly, we use a GeoLoader interface to load them only when needed
// by at least one rule.
func Compile[O Outbound](rules []TextRule, outbounds map[string]O,
	cacheSize int, geoLoader GeoLoader,
) (CompiledRuleSet[O], error) {
	compiledRules := make([]compiledRule[O], len(rules))
	for i, rule := range rules {
		outbound, ok := outbounds[strings.ToLower(rule.Outbound)]
		if !ok {
			return nil, &CompilationError{rule.LineNum, fmt.Sprintf("outbound %s not found", rule.Outbound)}
		}
		hm, errStr := compileHostMatcher(rule.Address, geoLoader)
		if errStr != "" {
			return nil, &CompilationError{rule.LineNum, errStr}
		}
		proto, startPort, endPort, ok := parseProtoPort(rule.ProtoPort)
		if !ok {
			return nil, &CompilationError{rule.LineNum, fmt.Sprintf("invalid protocol/port: %s", rule.ProtoPort)}
		}
		var hijackAddress net.IP
		if rule.HijackAddress != "" {
			hijackAddress = net.ParseIP(rule.HijackAddress)
			if hijackAddress == nil {
				return nil, &CompilationError{rule.LineNum, fmt.Sprintf("invalid hijack address (must be an IP address): %s", rule.HijackAddress)}
			}
		}
		compiledRules[i] = compiledRule[O]{outbound, hm, proto, startPort, endPort, hijackAddress}
	}

	// 使用 gcache 创建 LRU 缓存
	// GCache 是非泛型的，所以我们不能直接指定 O 类型，而是依赖于 interface{}
	// 这里我们选择 LRU 策略，并指定缓存大小
	cache := gcache.New(cacheSize).LRU().Build()

	return &compiledRuleSetImpl[O]{compiledRules, cache}, nil
}

// parseProtoPort parses the protocol and port from a protoPort string.
// protoPort must be in one of the following formats:
//
//	proto/port
//	proto/*
//	proto
//	*/port
//	*/*
//	*
//	[empty] (same as *)
//
// proto must be either "tcp" or "udp", case-insensitive.
func parseProtoPort(protoPort string) (Protocol, uint16, uint16, bool) {
	protoPort = strings.ToLower(protoPort)
	if protoPort == "" || protoPort == "*" || protoPort == "*/*" {
		return ProtocolBoth, 0, 0, true
	}
	parts := strings.SplitN(protoPort, "/", 2)
	if len(parts) == 1 {
		// No port, only protocol
		switch parts[0] {
		case "tcp":
			return ProtocolTCP, 0, 0, true
		case "udp":
			return ProtocolUDP, 0, 0, true
		default:
			return ProtocolBoth, 0, 0, false
		}
	} else {
		// Both protocol and port
		var proto Protocol
		var startPort, endPort uint16
		switch parts[0] {
		case "tcp":
			proto = ProtocolTCP
		case "udp":
			proto = ProtocolUDP
		case "*":
			proto = ProtocolBoth
		default:
			return ProtocolBoth, 0, 0, false
		}
		if parts[1] != "*" {
			// We allow either a single port or a range (e.g. "1000-2000")
			ports := strings.SplitN(strings.TrimSpace(parts[1]), "-", 2)
			if len(ports) == 1 {
				p64, err := strconv.ParseUint(parts[1], 10, 16)
				if err != nil {
					return ProtocolBoth, 0, 0, false
				}
				startPort = uint16(p64)
				endPort = start1Port
			} else {
				p64, err := strconv.ParseUint(ports[0], 10, 16)
				if err != nil {
					return ProtocolBoth, 0, 0, false
				}
				startPort = uint16(p64)
				p64, err = strconv.ParseUint(ports[1], 10, 16)
				if err != nil {
					return ProtocolBoth, 0, 0, false
				}
				endPort = uint16(p64)
				if startPort > endPort {
					return ProtocolBoth, 0, 0, false
				}
			}
		}
		return proto, startPort, endPort, true
	}
}

func compileHostMatcher(addr string, geoLoader GeoLoader) (hostMatcher, string) {
	addr = strings.ToLower(addr) // Normalize to lower case
	if addr == "*" || addr == "all" {
		// Match all hosts
		return &allMatcher{}, ""
	}
	if strings.HasPrefix(addr, "geoip:") {
		// GeoIP matcher
		country := addr[6:]
		if len(country) == 0 {
			return nil, "empty GeoIP country code"
		}
		gMap, err := geoLoader.LoadGeoIP()
		if err != nil {
			return nil, err.Error()
		}
		list, ok := gMap[country]
		if !ok || list == nil {
			return nil, fmt.Sprintf("GeoIP country code %s not found", country)
		}
		m, err := newGeoIPMatcher(list)
		if err != nil {
			return nil, err.Error()
		}
		return m, ""
	}
	if strings.HasPrefix(addr, "geosite:") {
		// GeoSite matcher
		name, attrs := parseGeoSiteName(addr[8:])
		if len(name) == 0 {
			return nil, "empty GeoSite name"
		}
		gMap, err := geoLoader.LoadGeoSite()
		if err != nil {
			return nil, err.Error()
		}
		list, ok := gMap[name]
		if !ok || list == nil {
			return nil, fmt.Sprintf("GeoSite name %s not found", name)
		}
		m, err := newGeositeMatcher(list, attrs)
		if err != nil {
			return nil, err.Error()
		}
		return m, ""
	}
	if strings.HasPrefix(addr, "suffix:") {
		// Domain suffix matcher
		suffix := addr[7:]
		if len(suffix) == 0 {
			return nil, "empty domain suffix"
		}
		return &domainMatcher{
			Pattern: suffix,
			Mode:    domainMatchSuffix,
		}, ""
	}
	if strings.Contains(addr, "/") {
		// CIDR matcher
		_, ipnet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, fmt.Sprintf("invalid CIDR address: %s", addr)
		}
		return &cidrMatcher{ipnet}, ""
	}
	if ip := net.ParseIP(addr); ip != nil {
		// Single IP matcher
		return &ipMatcher{ip}, ""
	}
	if strings.Contains(addr, "*") {
		// Wildcard domain matcher
		return &domainMatcher{
			Pattern: addr,
			Mode:    domainMatchWildcard,
		}, ""
	}
	// Nothing else matched, treat it as a non-wildcard domain
	return &domainMatcher{
		Pattern: addr,
		Mode:    domainMatchExact,
	}, ""
}

func parseGeoSiteName(s string) (string, []string) {
	parts := strings.Split(s, "@")
	base := strings.TrimSpace(parts[0])
	attrs := parts[1:]
	for i := range attrs {
		attrs[i] = strings.TrimSpace(attrs[i])
	}
	return base, attrs
}
