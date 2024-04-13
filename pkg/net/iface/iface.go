package iface

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
)

func Print() (*string, error) {
	var ifname string

	buf := new(bytes.Buffer)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces() error : %w", err)
	}

	for _, iface := range ifaces {
		if ifname == "" || ifname == iface.Name {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			buf.WriteString(fmt.Sprintf("%s: <%s> mtu=%d\n", iface.Name,
				strings.ToUpper(iface.Flags.String()), iface.MTU))

			if len(iface.HardwareAddr.String()) > 0 {
				buf.WriteString(fmt.Sprintf("\tether %s\n", iface.HardwareAddr.String()))
			}

			if len(addrs) > 0 {
				for _, addr := range addrs {
					buf.WriteString(fmt.Sprintf("\t%s\n", AddrInfo(addr)))
				}
			}
		}
	}

	str := buf.String()

	return &str, nil
}

func AddrInfo(addr net.Addr) string {
	ipAddr, ipNet, err := net.ParseCIDR(addr.String())
	if err != nil {
		return "unknown"
	}
	var scope string
	switch {
	case ipAddr.IsLoopback():
		scope = "loopback"
	case ipAddr.IsGlobalUnicast():
		scope = "global unicast"
	case ipAddr.IsMulticast():
		scope = "global multicast"
	case ipAddr.IsLinkLocalUnicast():
		scope = "link local unicast"
	case ipAddr.IsLinkLocalMulticast():
		scope = "link local multicast"
	case ipAddr.IsInterfaceLocalMulticast():
		scope = "interface multicast"
	case ipAddr.IsUnspecified():
		scope = "unspecified"
	default:
		scope = "unknown"
	}

	return fmt.Sprintf(
		"%s network=%s addr=%s mask=%v scope=%s",
		ipNet.Network(),
		ipNet.IP.String(),
		ipAddr.String(),
		ipAddr.DefaultMask(),
		scope,
	)
}

// Wildcard returns the opposite of the netmask for the network.
func Wildcard(mask net.IP) net.IP {
	var ipVal net.IP
	for _, octet := range mask {
		ipVal = append(ipVal, ^octet)
	}
	return ipVal
}

// LastIP calculates the highest address range starting at the given IP.
func LastIP(ip net.IP, mask net.IPMask) net.IP {
	ipIn := ip.To4() // is it an IPv4
	if ipIn == nil {
		ipIn = ip.To16() // is it IPv6
		if ipIn == nil {
			return nil
		}
	}
	var ipVal net.IP
	// apply network mask to each octet.
	for i, octet := range ipIn {
		ipVal = append(ipVal, octet|mask[i])
	}
	return ipVal
}

type LsDNS struct {
	resolver *net.Resolver
}

func NewLsdns() *LsDNS {
	return &LsDNS{net.DefaultResolver}
}

func (ls *LsDNS) ReverseLookup(ip string) error {
	names, err := ls.resolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return fmt.Errorf("resolver.LookupAddr(%s) error : %w", ip, err)
	}

	fmt.Println("Reverse lookup")
	fmt.Println("--------------")
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func (ls *LsDNS) HostLookup(host string) error {
	addrs, err := ls.resolver.LookupHost(context.Background(), host)
	if err != nil {
		return fmt.Errorf("resolver.LookupHost(%s) error : %w", host, err)
	}

	fmt.Println("Host lookup")
	fmt.Println("-----------")
	for _, addr := range addrs {
		fmt.Printf("%-30s%-20s\n", host, addr)
	}
	return nil
}

func (ls *LsDNS) NameServerLookup(host string) error {
	nses, err := ls.resolver.LookupNS(context.Background(), host)
	if err != nil {
		return fmt.Errorf("resolver.LookupNS(%s) error : %w", host, err)
	}
	fmt.Println("NS lookup")
	fmt.Println("---------")
	for _, ns := range nses {
		fmt.Printf("%-25s%-20s\n", host, ns.Host)
	}
	return nil
}

func (ls *LsDNS) MXLookup(host string) error {
	mxes, err := ls.resolver.LookupMX(context.Background(), host)
	if err != nil {
		return fmt.Errorf("resolver.LookupMX(%s) error : %w", host, err)
	}
	fmt.Println("MX lookup")
	fmt.Println("---------")
	for _, mx := range mxes {
		fmt.Printf("%-17s%-11s\n", host, mx.Host)
	}
	return nil
}

func (ls *LsDNS) TXTLookup(host string) error {
	txts, err := ls.resolver.LookupTXT(context.Background(), host)
	if err != nil {
		return fmt.Errorf("resolver.LookupTXT(%s) error : %w", host, err)
	}
	fmt.Println("TXT lookup")
	fmt.Println("---------")
	for _, txt := range txts {
		fmt.Printf("%-17s%-11s\n", host, txt)
	}
	return nil
}

func (ls *LsDNS) CNameLookup(host string) error {
	name, err := ls.resolver.LookupCNAME(context.Background(), host)
	if err != nil {
		return fmt.Errorf("resolver.LookupCNAME(%s) error : %w", host, err)
	}
	fmt.Println("CNAME lookup")
	fmt.Println("------------")
	fmt.Printf("%s: %s\n", host, name)
	return nil
}
