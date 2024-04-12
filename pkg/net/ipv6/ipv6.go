package ipv6

import (
	"net"
)

func IsNetIPv6(ip net.IP) bool {
	return ip.To16() != nil
}
