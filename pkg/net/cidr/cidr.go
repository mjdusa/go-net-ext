package cidr

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/mjdusa/go-ui-example/pkg/net/ipv4"
)

const (
	NetBitCount              = 32
	MaxNetBitSize            = 32
	ParserBase        int    = 10
	Parser8BitSize    int    = 8
	UInt32Max         uint32 = 0xFFFFFFFF // 4294967295 (32 bits).
	PowBase           uint32 = 2
	CIDRSeparatorChar string = "/"
	ExpectedCIDRParts int    = 2
	MinIPv4CIDR              = "0.0.0.0/0"
	MaxIPv4CIDR              = "255.255.255.255/32"
	MinIPv6CIDR              = "0000:0000:0000:0000:0000:0000:0000:0000/0"
	MaxIPv6CIDR              = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF/128"
)

var (
	CIDRList []string = []string{
		"255.255.255.255/32",
		"255.255.255.254/31",
		"255.255.255.252/30",
		"255.255.255.248/29",
		"255.255.255.240/28",
		"255.255.255.224/27",
		"255.255.255.192/26",
		"255.255.255.128/25",
		"255.255.255.0/24",
		"255.255.254.0/23",
		"255.255.252.0/22",
		"255.255.248.0/21",
		"255.255.240.0/20",
		"255.255.224.0/19",
		"255.255.192.0/18",
		"255.255.128.0/17",
		"255.255.0.0/16",
		"255.254.0.0/15",
		"255.252.0.0/14",
		"255.248.0.0/13",
		"255.240.0.0/12",
		"255.224.0.0/11",
		"255.192.0.0/10",
		"255.128.0.0/9",
		"255.0.0.0/8",
		"254.0.0.0/7",
		"252.0.0.0/6",
		"248.0.0.0/5",
		"240.0.0.0/4",
		"224.0.0.0/3",
		"192.0.0.0/2",
		"128.0.0.0/1",
		"0.0.0.0/0",
	}
)

type IPv4CIDR struct { // CIDR - Classless Inter Domain Routing.
	CIDRNotation string
	NetworkBits  uint8 // 0-32
	HostBits     uint8 // 0-32
	Network      uint32
	Broadcast    uint32
	Subnet       uint32
	Wildcard     uint32
	MaxAddresses uint32
	MaxSubnets   uint32
}

// Parse IPv4 CIDR.
func ParseIPv4CIDR(fullCIDR string) (cidr *IPv4CIDR, err error) {
	// Validate format.
	cidrParts := strings.Split(fullCIDR, CIDRSeparatorChar)
	if len(cidrParts) != ExpectedCIDRParts {
		return nil, fmt.Errorf("invald parts list [%d]", len(cidrParts))
	}

	// Validate IPv4.
	ip := cidrParts[0]
	if !ipv4.IsIPv4(ip) {
		return nil, fmt.Errorf("invald IPv4 Address [%s]", ip)
	}

	// Validate CIDR Mask.
	netBits64, err := strconv.ParseUint(cidrParts[1], ParserBase, Parser8BitSize)
	if err != nil {
		return nil, err
	} else if netBits64 > MaxNetBitSize {
		return nil, fmt.Errorf("Network bits out of range [%s]", cidrParts[1])
	}

	ipv4cidr := IPv4CIDR{
		CIDRNotation: fullCIDR,
	}

	ipVal := ipv4.IPv4ToUint32(ip)
	netBits8 := uint8(netBits64)
	netBits32 := uint32(netBits64)

	ipv4cidr.NetworkBits = netBits8              // 0 - 32
	ipv4cidr.HostBits = MaxNetBitSize - netBits8 // 0 - 32
	ipv4cidr.MaxAddresses = PowUint32(PowBase, uint32(ipv4cidr.HostBits))
	if netBits32 != MaxNetBitSize {
		ipv4cidr.MaxAddresses = ipv4cidr.MaxAddresses - 2
	}
	ipv4cidr.MaxSubnets = PowUint32(PowBase, uint32(ipv4cidr.HostBits))
	ipv4cidr.Network = ipVal & netBits32
	ipv4cidr.Broadcast = ipVal | (UInt32Max >> netBits32)
	ipv4cidr.Wildcard = UInt32Max >> netBits32
	ipv4cidr.Subnet = ipv4cidr.Wildcard ^ UInt32Max
	ipv4cidr.Network = ipVal & ipv4cidr.Subnet
	ipv4cidr.CIDRNotation = fmt.Sprintf("%s/%d", ipv4.Uint32ToIPv4(ipv4cidr.Network), ipv4cidr.NetworkBits)

	return &ipv4cidr, err
}

func PowUint8(x, y uint8) uint8 {
	return uint8(math.Pow(float64(x), float64(y)))
}

func PowUint32(x, y uint32) uint32 {
	return uint32(math.Pow(float64(x), float64(y)))
}

func PowUint64(x, y uint64) uint64 {
	return uint64(math.Pow(float64(x), float64(y)))
}

// Convert IPv4 range into CIDR
func IPv4RangeToCIDRRange(ipStart string, ipEnd string) (cidrs []string, err error) {
	cidr2mask := []uint32{
		0x00000000, 0x80000000, 0xC0000000,
		0xE0000000, 0xF0000000, 0xF8000000,
		0xFC000000, 0xFE000000, 0xFF000000,
		0xFF800000, 0xFFC00000, 0xFFE00000,
		0xFFF00000, 0xFFF80000, 0xFFFC0000,
		0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
		0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
		0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
		0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
		0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
		0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
	}

	ipStartUint32 := ipv4.IPv4ToUint32(ipStart)
	ipEndUint32 := ipv4.IPv4ToUint32(ipEnd)

	if ipStartUint32 > ipEndUint32 {
		return []string{}, fmt.Errorf("start IP:%s must be less than end IP:%s", ipStart, ipEnd)
	}

	for ipEndUint32 >= ipStartUint32 {
		maxSize := 32
		for maxSize > 0 {
			maskedBase := ipStartUint32 & cidr2mask[maxSize-1]

			if maskedBase != ipStartUint32 {
				break
			}

			maxSize--
		}

		x := math.Log(float64(ipEndUint32-ipStartUint32+1)) / math.Log(2)
		maxDiff := 32 - int(math.Floor(x))
		if maxSize < maxDiff {
			maxSize = maxDiff
		}

		cidrs = append(cidrs, ipv4.Uint32ToIPv4(ipStartUint32)+CIDRSeparatorChar+strconv.Itoa(maxSize))

		ipStartUint32 += uint32(math.Exp2(float64(32 - maxSize)))
	}

	return cidrs, err
}
