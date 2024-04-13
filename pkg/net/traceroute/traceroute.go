// Package traceroute provides functions for executing a tracroute to a remote host.
//
//	Original code from https://github.com/aeden/traceroute
package traceroute

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const DefaultPort = 33434
const DefaultMaxHops = 64
const DefaultFirstHop = 1
const DefaultTimeoutMS = 500
const DefaultRetries = 3
const DefaultPacketSize = 52

// Return the first non-loopback address as a 4 byte IP address. This address
// is used for sending packets out.
func GetLocalInterfaceAddress() ([4]byte, error) {
	var addr [4]byte

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return addr, fmt.Errorf("net.InterfaceAddrs() error : %w", err)
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				copy(addr[:], ipnet.IP.To4())
				return addr, nil
			}
		}
	}

	return addr, errors.New("you do not appear to be connected to the Internet")
}

// Given a host name convert it to a 4 byte IP address.
func DestAddr(dest string) ([4]byte, error) {
	var destAddr [4]byte

	addrs, err := net.LookupHost(dest)
	if err != nil {
		return destAddr, fmt.Errorf("net.LookupHost(%s) error : %w", dest, err)
	}

	addr := addrs[0]

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return destAddr, fmt.Errorf("net.ResolveIPAddr(\"ip\", \"%s\") error : %w", addr, err)
	}

	copy(destAddr[:], ipAddr.IP.To4())

	return destAddr, nil
}

// Options - TraceRoute options.
type Options struct {
	port       int
	maxHops    int
	firstHop   int
	timeoutMs  int
	retries    int
	packetSize int
}

func (options *Options) Port() int {
	if options.port == 0 {
		options.port = DefaultPort
	}
	return options.port
}

func (options *Options) SetPort(port int) {
	options.port = port
}

func (options *Options) MaxHops() int {
	if options.maxHops == 0 {
		options.maxHops = DefaultMaxHops
	}
	return options.maxHops
}

func (options *Options) SetMaxHops(maxHops int) {
	options.maxHops = maxHops
}

func (options *Options) FirstHop() int {
	if options.firstHop == 0 {
		options.firstHop = DefaultFirstHop
	}
	return options.firstHop
}

func (options *Options) SetFirstHop(firstHop int) {
	options.firstHop = firstHop
}

func (options *Options) TimeoutMs() int {
	if options.timeoutMs == 0 {
		options.timeoutMs = DefaultTimeoutMS
	}
	return options.timeoutMs
}

func (options *Options) SetTimeoutMs(timeoutMs int) {
	options.timeoutMs = timeoutMs
}

func (options *Options) Retries() int {
	if options.retries == 0 {
		options.retries = DefaultRetries
	}
	return options.retries
}

func (options *Options) SetRetries(retries int) {
	options.retries = retries
}

func (options *Options) PacketSize() int {
	if options.packetSize == 0 {
		options.packetSize = DefaultPacketSize
	}
	return options.packetSize
}

func (options *Options) SetPacketSize(packetSize int) {
	options.packetSize = packetSize
}

// Hop - TraceRoute Hop.
type Hop struct {
	Success     bool
	Address     [4]byte
	Host        string
	N           int
	ElapsedTime time.Duration
	TTL         int
}

func (hop *Hop) AddressString() string {
	return fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
}

func (hop *Hop) HostOrAddressString() string {
	hostOrAddr := hop.AddressString()
	if hop.Host != "" {
		hostOrAddr = hop.Host
	}
	return hostOrAddr
}

// Result type.
type Result struct {
	SrcAddr syscall.Sockaddr
	DstAddr syscall.Sockaddr
	Hops    []Hop
}

/*
func notify(hop Hop, channels []chan Hop) {
	for _, c := range channels {
		c <- hop
	}
}

func closeNotify(channels []chan Hop) {
	for _, c := range channels {
		close(c)
	}
}

// TraceRoute uses the given dest (hostname) and options to execute a TraceRoute
// from your machine to the remote host.
//
// Outbound packets are UDP packets and inbound packets are ICMP.
//
// Returns a Result which contains an array of hops. Each hop includes
// the elapsed time and its IP address.
func TraceRouteIPv4(dest string, options *TraceRouteOptions,
	c ...chan Hop) (result Result, err error) {
	result.Hops = []Hop{}

	localInterfaceAddress, err := getLocalInterfaceAddress()
	if err != nil {
		return
	}
	result.SrcAddr = &syscall.SockaddrInet4{Port: options.Port(), Addr: localInterfaceAddress}

	destinationAddress, err := destAddr(dest)
	if err != nil {
		return
	}
	result.DstAddr = &syscall.SockaddrInet4{Port: options.Port(), Addr: destinationAddress}

	return TraceRoute(result.SrcAddr, result.DstAddr, options, c...)
}

func TraceRoute(srcAddr syscall.Sockaddr, dstAddr syscall.Sockaddr, options *TraceRouteOptions,
	c ...chan Hop) (result Result, err error) {
	result.SrcAddr = srcAddr
	result.DstAddr = dstAddr
	result.Hops = []Hop{}

	timeoutMs := (int64)(options.TimeoutMs())
	tv := syscall.NsecToTimeval(1000 * 1000 * timeoutMs)

	ttl := options.FirstHop()
	retry := 0
	for {
		//log.Println("TTL: ", ttl)
		start := time.Now()

		// Set up the socket to receive packets
		recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err != nil {
			return result, err
		}

		// Set up the socket to send packets out.
		sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			return result, err
		}

		// Set send TTL
		syscall.SetsockoptInt(sendSocket, syscall.IPPROTO_HOPOPTS, syscall.IP_TTL, ttl)

		// Sets response timeout
		syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		// Defer socket closes
		defer syscall.Close(recvSocket)
		defer syscall.Close(sendSocket)

		// Bind to the local socket to listen for ICMP packets
		syscall.Bind(recvSocket, result.SrcAddr)

		// Send a single null byte UDP packet
		syscall.Sendto(sendSocket, []byte{0x0}, 0, result.DstAddr)

		var p = make([]byte, options.PacketSize())
		n, from, err := syscall.Recvfrom(recvSocket, p, 0)
		elapsed := time.Since(start)
		if err == nil {
			currAddr := from.(*syscall.SockaddrInet4).Addr

			hop := Hop{Success: true, Address: currAddr, N: n, ElapsedTime: elapsed, TTL: ttl}

			// TODO: this reverse lookup appears to have some standard timeout that is relatively
			// high. Consider switching to something where there is greater control.
			//currHost, err := net.LookupAddr(hop.AddressString())
			//if err == nil {
			//	hop.Host = currHost[0]
			//}

			{
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{
							Timeout: time.Millisecond * time.Duration(10000),
						}
						return d.DialContext(ctx, network, "8.8.8.8:53")
					},
				}

				ctx := context.Background()
				deadlineCtx := ctx
				if deadline, ok := ctx.Deadline(); ok {
					var cancelFunc func()
					deadlineCtx, cancelFunc = context.WithDeadline(ctx, deadline.Add(-10*time.Millisecond))
					defer cancelFunc()
				}

				currHost, err := resolver.LookupAddr(deadlineCtx, hop.AddressString())
				if err == nil {
					hop.Host = currHost[0]
				}
			}

			notify(hop, c)

			result.Hops = append(result.Hops, hop)

			ttl += 1
			retry = 0

			if ttl > options.MaxHops() || currAddr == destAddr {
				closeNotify(c)
				return result, nil
			}
		} else {
			retry += 1
			if retry > options.Retries() {
				notify(Hop{Success: false, TTL: ttl}, c)
				ttl += 1
				retry = 0
			}

			if ttl > options.MaxHops() {
				closeNotify(c)
				return result, nil
			}
		}
	}
}
*/
