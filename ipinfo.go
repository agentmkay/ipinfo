package ipinfo

import (
	"net"
	"strings"
)

// IPDetails contains information about an IP address
type IPDetails struct {
	IP         net.IP
	IsPrivate  bool
	IsLoopback bool
	IsIPv4     bool
	IsIPv6     bool
	Hostnames  []string
	ReverseDNS []string
	CommonUses []string
	Version    string
}

// Lookup performs IP lookup and returns detailed information
func Lookup(target string) ([]IPDetails, error) {
	ips, err := resolveTarget(target)
	if err != nil {
		return nil, err
	}

	var results []IPDetails
	for _, ip := range ips {
		details := analyzeIP(ip)
		results = append(results, details)
	}

	return results, nil
}

func resolveTarget(target string) ([]net.IP, error) {
	// First try to resolve as hostname
	ips, err := net.LookupIP(target)
	if err != nil {
		// If it fails, try to parse as IP address
		if ip := net.ParseIP(target); ip != nil {
			ips = []net.IP{ip}
		} else {
			return nil, err
		}
	}
	return ips, nil
}

func analyzeIP(ip net.IP) IPDetails {
	details := IPDetails{
		IP: ip,
	}

	// Basic properties
	details.IsPrivate = ip.IsPrivate()
	details.IsLoopback = ip.IsLoopback()
	details.IsIPv4 = ip.To4() != nil
	details.IsIPv6 = !details.IsIPv4

	if details.IsIPv4 {
		details.Version = "IPv4"
		details.CommonUses = getIPv4CommonUses(ip)
	} else {
		details.Version = "IPv6"
		details.CommonUses = getIPv6CommonUses(ip)
	}

	// Hostnames
	if hostnames, err := net.LookupAddr(ip.String()); err == nil {
		details.Hostnames = hostnames
	}

	// Reverse DNS
	if ptr, err := net.LookupAddr(ip.String()); err == nil {
		details.ReverseDNS = ptr
	}

	return details
}

func getIPv4CommonUses(ip net.IP) []string {
	var uses []string
	ipStr := ip.String()

	switch {
	case strings.HasPrefix(ipStr, "192.168."):
		uses = append(uses, "Private network (RFC 1918)")
	case strings.HasPrefix(ipStr, "10."):
		uses = append(uses, "Private network (RFC 1918)")
	case strings.HasPrefix(ipStr, "172.16.") || strings.HasPrefix(ipStr, "172.17.") ||
		strings.HasPrefix(ipStr, "172.18.") || strings.HasPrefix(ipStr, "172.19.") ||
		strings.HasPrefix(ipStr, "172.20.") || strings.HasPrefix(ipStr, "172.21.") ||
		strings.HasPrefix(ipStr, "172.22.") || strings.HasPrefix(ipStr, "172.23.") ||
		strings.HasPrefix(ipStr, "172.24.") || strings.HasPrefix(ipStr, "172.25.") ||
		strings.HasPrefix(ipStr, "172.26.") || strings.HasPrefix(ipStr, "172.27.") ||
		strings.HasPrefix(ipStr, "172.28.") || strings.HasPrefix(ipStr, "172.29.") ||
		strings.HasPrefix(ipStr, "172.30.") || strings.HasPrefix(ipStr, "172.31."):
		uses = append(uses, "Private network (RFC 1918)")
	case strings.HasPrefix(ipStr, "169.254."):
		uses = append(uses, "Link-local (APIPA)")
	case strings.HasPrefix(ipStr, "224."):
		uses = append(uses, "Multicast")
	case strings.HasPrefix(ipStr, "127."):
		uses = append(uses, "Loopback")
	case strings.HasPrefix(ipStr, "100.64."):
		uses = append(uses, "Carrier-grade NAT (RFC 6598)")
	default:
		uses = append(uses, "Public address")
	}

	return uses
}

func getIPv6CommonUses(ip net.IP) []string {
	var uses []string
	ipStr := ip.String()

	switch {
	case strings.HasPrefix(ipStr, "::1"):
		uses = append(uses, "Loopback")
	case strings.HasPrefix(ipStr, "fe80:"):
		uses = append(uses, "Link-local")
	case strings.HasPrefix(ipStr, "fc00:") || strings.HasPrefix(ipStr, "fd00:"):
		uses = append(uses, "Unique local address (ULA)")
	case strings.HasPrefix(ipStr, "ff00:"):
		uses = append(uses, "Multicast")
	case strings.HasPrefix(ipStr, "2001:0:"):
		uses = append(uses, "Teredo tunneling")
	case strings.HasPrefix(ipStr, "2001:db8:"):
		uses = append(uses, "Documentation")
	case strings.HasPrefix(ipStr, "2002:"):
		uses = append(uses, "6to4")
	default:
		uses = append(uses, "Global unicast")
	}

	return uses
}
