package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

type FullAddress struct {
	Address string
	Hosts   []string
	Error   error
}

type FullHostResponse struct {
	Host             string
	LookupNameServer string
	TimeoutMS        int64
	Addresses        []FullAddress
}

type FullDomainResponse struct {
	DomainName       string
	LookupNameServer string
	TimeoutMS        int64
	CNAME            string
	Host             []FullAddress
	IP               []net.IP
	IPAddr           []net.IPAddr
	MX               []*net.MX
	NS               []*net.NS
	SRVHost          string
	SRV              []*net.SRV
	TXT              []string
}

func FullResolve(ctx context.Context, host string, lookupNameServer string,
	timeoutMS int64) (*FullHostResponse, error) {
	response := FullHostResponse{
		Host:             host,
		LookupNameServer: lookupNameServer,
		TimeoutMS:        timeoutMS,
	}

	timeout := time.Millisecond * time.Duration(response.TimeoutMS)

	// Create a custom resolver.
	resolver := CreateCustomResolver(true, timeout, response.LookupNameServer)

	deadlineCtx := ctx
	if deadline, ok := ctx.Deadline(); ok {
		var cancelFunc func()
		deadlineCtx, cancelFunc = context.WithDeadline(ctx, deadline.Add(timeout))
		defer cancelFunc()
	}

	addresses, herr := resolver.LookupHost(deadlineCtx, response.Host)
	if herr != nil {
		return &response, fmt.Errorf("resolver.LookupHost(%s) error : %w", response.Host, herr)
	}

	for _, address := range addresses {
		fullAddress := FullAddress{
			Address: address,
		}

		responseHosts, aerr := resolver.LookupAddr(deadlineCtx, fullAddress.Address)
		if aerr != nil {
			fullAddress.Hosts = []string{aerr.Error()}
		} else {
			fullAddress.Hosts = responseHosts
		}

		response.Addresses = append(response.Addresses, fullAddress)
	}

	return &response, nil
}

func CreateCustomResolver(preferGo bool, timeout time.Duration, lookupNameServer string) *net.Resolver {
	resolver := net.Resolver{
		PreferGo: preferGo,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) { //nolint:revive,lll  // Function must implement Dial interface.
			dlr := net.Dialer{
				Timeout: timeout,
			}

			return dlr.DialContext(ctx, network, lookupNameServer)
		},
	}

	return &resolver
}

// DomainLookup - network must be one of "ip", "ip4" or "ip6", service "", protocol must be one of "tcp" or "udp".
func DomainLookup(ctx context.Context, domainName string, network string, service string, protocol string,
	lookupNameServer string, timeoutMS int64) (*FullDomainResponse, error) {
	var err error

	response := FullDomainResponse{
		DomainName:       domainName,
		LookupNameServer: lookupNameServer,
		TimeoutMS:        timeoutMS,
	}

	timeout := time.Millisecond * time.Duration(response.TimeoutMS)
	resolver := CreateCustomResolver(true, timeout, response.LookupNameServer)
	deadlineCtx := CreateDeadlinContext(ctx, timeout)

	addrs, herr := resolver.LookupHost(deadlineCtx, domainName)
	if herr != nil {
		err = fmt.Errorf("LookupHost error: %w", herr)
	}

	response.Host = LookupAddresses(deadlineCtx, addrs, resolver)

	cname, cerr := resolver.LookupCNAME(deadlineCtx, domainName)
	if cerr != nil {
		err = fmt.Errorf("LookupCNAME error: %w", cerr)
	} else {
		response.CNAME = cname
	}

	ip, ierr := resolver.LookupIP(deadlineCtx, network, domainName)
	if ierr != nil {
		err = fmt.Errorf("LookupIP error: %w", ierr)
	} else {
		response.IP = ip
	}

	mx, merr := resolver.LookupMX(deadlineCtx, domainName)
	if merr != nil {
		err = fmt.Errorf("LookupMX error: %w", merr)
	} else {
		response.MX = mx
	}

	ns, nerr := resolver.LookupNS(deadlineCtx, domainName)
	if nerr != nil {
		err = fmt.Errorf("LookupNS error: %w", nerr)
	} else {
		response.NS = ns
	}

	svcHost, srv, serr := resolver.LookupSRV(deadlineCtx, service, protocol, domainName)
	if serr != nil {
		var dnsError *net.DNSError
		if errors.As(serr, &dnsError) && serr.Error() != "no such host" {
			err = fmt.Errorf("LookupSRV error: %w", serr)
		} else {
			response.SRVHost = serr.Error()
		}
	} else {
		response.SRVHost = svcHost
		response.SRV = srv
	}

	txt, terr := resolver.LookupTXT(deadlineCtx, domainName)
	if terr != nil {
		err = fmt.Errorf("LookupTXT error: %w", terr)
	} else {
		response.TXT = txt
	}

	return &response, err
}

func LookupAddresses(ctx context.Context, addrs []string, resolver *net.Resolver) []FullAddress {
	fullAddresses := []FullAddress{}

	for _, addr := range addrs {
		fullAddress := FullAddress{
			Address: addr,
		}

		responseHosts, aerr := resolver.LookupAddr(ctx, fullAddress.Address)
		if aerr != nil {
			fullAddress.Error = aerr
		} else {
			fullAddress.Hosts = responseHosts
		}

		fullAddresses = append(fullAddresses, fullAddress)
	}

	return fullAddresses
}

func LookupResourceRecord(ctx context.Context, resolver *net.Resolver, rrType string, rrAddr string) ([]string, error) {
	switch rrType {
	case "TXT":
		return resolver.LookupTXT(ctx, rrAddr) //nolint:wrapcheck  // No need to wrap the error.
	default:
		return []string{}, fmt.Errorf("unsupported resource record type: %s", rrType)
	}
}

func CreateDeadlinContext(ctx context.Context, timeout time.Duration) context.Context {
	deadlineCtx := ctx

	if deadline, ok := ctx.Deadline(); ok {
		var cancelFunc func()
		deadlineCtx, cancelFunc = context.WithDeadline(ctx, deadline.Add(timeout))
		defer cancelFunc()
	}

	return deadlineCtx
}

/*
func Address(addr string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	response := ""

	names, err := net.LookupAddr(addr)
	if err != nil {
		response = fmt.Sprintf("%serror: %s\n", indentStr, err.Error())
		return response
	}

	if len(names) == 0 {
		response = response + fmt.Sprintf("%sno record\n", indentStr)
	} else {
		for _, name := range names {
			response = response + fmt.Sprintf("%s[ADDR] %s\n", indentStr, name)
		}
	}

	return response
}

func CName(url string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	response := ""

	cname, err := net.LookupCNAME(url)
	if err != nil {
		response = fmt.Sprintf("%serror: %s\n", indentStr, err.Error())
		return response
	}

	response = fmt.Sprintf("%s[CNAME] %s\n", indentStr, cname)

	return response
}

func IP(url string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	response := ""

	ips, err := net.LookupIP(url)
	if err != nil {
		response = fmt.Sprintf("%serror: %s\n", indentStr, err.Error())
		return response
	}

	if len(ips) == 0 {
		response = response + fmt.Sprintf("%sno record\n", indentStr)
	} else {
		for _, ip := range ips {
			response = response + fmt.Sprintf("%s[IP] %s\n%s\n", indentStr, ip,
				address(ip.String(), indent+2))
		}
	}

	return response
}

func MX(url string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	response := ""

	mxs, err := net.LookupMX(url)
	if err != nil {
		response = fmt.Sprintf("%serror: %s\n", indentStr, err.Error())
		return response
	}

	if len(mxs) == 0 {
		response = response + fmt.Sprintf("%sno record\n", indentStr)
	} else {
		for _, mx := range mxs {
			response = response + fmt.Sprintf("%s[MX] %s %v\n", indentStr, mx.Host, mx.Pref)
		}
	}

	return response
}

func NS(url string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	response := ""

	nss, err := net.LookupNS(url)
	if err != nil {
		response = fmt.Sprintf("%serror: %s\n", indentStr, err.Error())
		return response
	}

	if len(nss) == 0 {
		response = response + fmt.Sprintf("%sno record\n", indentStr)
	} else {
		for _, ns := range nss {
			response = response + fmt.Sprintf("%s[NS] %s\n", indentStr, ns.Host)
		}
	}

	return response
}

func TXT(url string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	response := ""

	txts, err := net.LookupTXT(url)
	if err != nil {
		response = fmt.Sprintf("%serror: %s\n", indentStr, err.Error())
		return response
	}

	if len(txts) == 0 {
		response = response + fmt.Sprintf("%sno record\n", indentStr)
	} else {
		for _, txt := range txts {
			if strings.Contains(txt, "v=DMARC1") {
				response = response + fmt.Sprintf("%s[DMARC] %s\n", indentStr, txt)
			} else {
				response = response + fmt.Sprintf("%s[TXT] %s\n", indentStr, txt)
			}
		}
	}

	return response
}
*/
