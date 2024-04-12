package ipv4

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	IPv4OctetSeparator        = "." // IPv4 octet separator.
	IPv4AddressLength         = 4   // IPv4 address length.
	IPv4OctetMin              = 0   // IPv4 octet min.
	IPv4OctetMax              = 255 // IPv4 octet max.
	ParserBase10              = 10  // Parser base 10.
	ParserBit32Size           = 32  // Parser bit 32 size.
	Shift3Byte                = 24
	Shift2Byte                = 16
	Shift1Byte                = 8
	Shift0Byte                = 0
	BitMaskByte3       uint32 = 0xFF000000
	BitMaskByte2       uint32 = 0x00FF0000
	BitMaskByte1       uint32 = 0x0000FF00
	BitMaskByte0       uint32 = 0x000000FF
	BitMask3Byte       uint32 = 0x00FFFFFF
	BitMask2Byte       uint32 = 0x0000FFFF
	BitMask1Byte       uint32 = 0x000000FF
)

func IsNetIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// Is valid IPv4 Address string.
func IsIPv4(ipAddressStr string) bool {
	trimmed := strings.TrimSpace(ipAddressStr)
	parts := strings.Split(trimmed, IPv4OctetSeparator)
	if len(parts) != IPv4AddressLength {
		return false
	}

	for _, part := range parts {
		if eger, err := strconv.Atoi(part); err == nil {
			if eger < IPv4OctetMin || eger > IPv4OctetMax {
				return false
			}
		} else {
			return false
		}
	}

	return true
}

// Convert IPv4 to uint32.
func IPv4ToUint32(ipv4 string) uint32 {
	ipOctets := [IPv4AddressLength]uint64{}

	for i, v := range strings.SplitN(ipv4, IPv4OctetSeparator, IPv4AddressLength) {
		ipOctets[i], _ = strconv.ParseUint(v, ParserBase10, ParserBit32Size)
	}

	result := (ipOctets[0] << Shift3Byte) | (ipOctets[1] << Shift2Byte) | (ipOctets[2] << Shift1Byte) | ipOctets[3]

	return uint32(result)
}

// Convert uint32 to IP.
func Uint32ToIPv4(ipUint32 uint32) (ip string) {
	ip = fmt.Sprintf("%d.%d.%d.%d",
		ipUint32>>Shift3Byte,
		(ipUint32&BitMask3Byte)>>Shift2Byte,
		(ipUint32&BitMask2Byte)>>Shift1Byte,
		ipUint32&BitMask1Byte)
	return ip
}

func Uint32PrintBinary(ip uint32) string {
	return fmt.Sprintf("%08b.%08b.%08b.%08b", ip>>Shift3Byte,
		(ip&BitMask3Byte)>>Shift2Byte, (ip&BitMask2Byte)>>Shift1Byte, ip&BitMask1Byte)
}

func BytePrintBinary(by byte) string {
	return fmt.Sprintf("%08b", by)
}

func GetIPv4NetworkClass(ip string) string {
	parts := strings.Split(ip, ".")
	firstOctet, err := strconv.Atoi(parts[0])
	if err != nil {
		return "Invalid IP"
	}

	switch {
	case firstOctet >= 0 && firstOctet <= 127:
		return "Class A"
	case firstOctet >= 128 && firstOctet <= 191:
		return "Class B"
	case firstOctet >= 192 && firstOctet <= 223:
		return "Class C"
	case firstOctet >= 224 && firstOctet <= 239:
		return "Class D" // multicast
	case firstOctet >= 240 && firstOctet <= 255:
		return "Class E" // Reserved for future use.
	default:
		return "Invalid IP"
	}
}
