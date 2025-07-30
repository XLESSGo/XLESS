package tun

import (
	"errors"
	"fmt"
	"net"
	"go.uber.org/zap"

	"github.com/XLESSGo/water"
)

type Server struct {
	EventLogger EventLogger
	Logger      *zap.Logger
	IfName      string
	MTU         uint32
	Inet4Address []string
	Inet6Address []string
	Timeout      int64
	AutoRoute    bool
	StructRoute  bool
	Inet4RouteAddress        []string
	Inet6RouteAddress        []string
	Inet4RouteExcludeAddress []string
	Inet6RouteExcludeAddress []string
}

type EventLogger interface {
	TCPRequest(addr, reqAddr string)
	TCPError(addr, reqAddr string, err error)
	UDPRequest(addr string)
	UDPError(addr string, err error)
}

func (s *Server) Serve() error {
	if !isIPv6Supported() {
		s.Logger.Warn("tun-pre-check", zap.String("msg", "IPv6 is not supported or enabled on this system, TUN device is created without IPv6 support."))
		s.Inet6Address = nil
	}

	config := water.Config{DeviceType: water.TUN}
	// DO NOT set config.MTU! water.Config does not have MTU field.

	// s.MTU should be used for buffer size only
	mtu := s.MTU
	if mtu == 0 {
		mtu = 1500
	}

	tunIf, err := water.New(config)
	if err != nil {
		return fmt.Errorf("failed to create tun interface: %w", err)
	}
	defer tunIf.Close()

	s.Logger.Info("TUN interface created", zap.String("name", tunIf.Name()))

	// If you want to set MTU, you must use OS commands after creating device.
	// Example (Linux): exec.Command("ip", "link", "set", "dev", tunIf.Name(), "mtu", strconv.Itoa(int(mtu)))

	buf := make([]byte, mtu)
	for {
		n, err := tunIf.Read(buf)
		if err != nil {
			s.Logger.Error("Error reading from TUN", zap.Error(err))
			return err
		}
		if n < 1 {
			continue
		}
		go s.handlePacket(buf[:n])
	}
}

func (s *Server) handlePacket(pkt []byte) {
	if len(pkt) < 1 {
		return
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		s.handleIPv4(pkt)
	case 6:
		s.handleIPv6(pkt)
	default:
		s.Logger.Warn("Unknown IP version", zap.Uint8("version", version))
	}
}

func (s *Server) handleIPv4(pkt []byte) {
	if len(pkt) < 20 {
		s.Logger.Warn("IPv4 packet too short")
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl {
		s.Logger.Warn("IPv4 header length mismatch")
		return
	}
	proto := pkt[9]
	src := net.IP(pkt[12:16]).String()
	dst := net.IP(pkt[16:20]).String()
	switch proto {
	case 6: // TCP
		if s.EventLogger != nil {
			s.EventLogger.TCPRequest(src, dst)
			defer s.EventLogger.TCPError(src, dst, errors.New("TCP forwarding not implemented"))
		}
	case 17: // UDP
		if s.EventLogger != nil {
			s.EventLogger.UDPRequest(src)
			defer s.EventLogger.UDPError(src, errors.New("UDP forwarding not implemented"))
		}
	default:
		s.Logger.Debug("IPv4 protocol not handled", zap.Uint8("proto", proto))
	}
}

func (s *Server) handleIPv6(pkt []byte) {
	if len(pkt) < 40 {
		s.Logger.Warn("IPv6 packet too short")
		return
	}
	src := net.IP(pkt[8:24]).String()
	dst := net.IP(pkt[24:40]).String()
	nextHeader := pkt[6]
	switch nextHeader {
	case 6: // TCP
		if s.EventLogger != nil {
			s.EventLogger.TCPRequest(src, dst)
			defer s.EventLogger.TCPError(src, dst, errors.New("TCP forwarding not implemented"))
		}
	case 17: // UDP
		if s.EventLogger != nil {
			s.EventLogger.UDPRequest(src)
			defer s.EventLogger.UDPError(src, errors.New("UDP forwarding not implemented"))
		}
	default:
		s.Logger.Debug("IPv6 protocol not handled", zap.Uint8("nextHeader", nextHeader))
	}
}

// interfaceFinder: 保留接口，用于系统网卡查询
type interfaceFinder struct{}

func (f *interfaceFinder) InterfaceIndexByName(name string) (int, error) {
	ifce, err := net.InterfaceByName(name)
	if err != nil {
		return -1, err
	}
	return ifce.Index, nil
}

func (f *interfaceFinder) InterfaceNameByIndex(index int) (string, error) {
	ifce, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", err
	}
	return ifce.Name, nil
}
