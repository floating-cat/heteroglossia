package cli

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"text/tabwriter"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport/np_carrier"
	"github.com/floating-cat/heteroglossia/transport/sq_carrier"
	"github.com/floating-cat/heteroglossia/transport/ss_carrier"
	"github.com/floating-cat/heteroglossia/transport/tr_carrier"
	"github.com/floating-cat/heteroglossia/util/passwordutil"
)

// protocolInfo is what a client needs to connect to one protocol of an inbound
// or outbound.
type protocolInfo struct {
	protocol string
	// network is TCP, UDP, TLS (over TCP) or QUIC (over UDP)
	network string
	port    uint16
	// "" is used when a username is empty.
	// "-" is used when a username is not required by this protocol.
	username string
	password string
}

// PrintInfo prints the connection info in config, which is parsed from
// configFile: a description of the output, the protocols, ports, and
// credentials of the inbounds and outbounds so that other clients can be set
// up to connect to them, and the profiling port if profiling is enabled.
func PrintInfo(w io.Writer, configFile string, config *conf.Config) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Below are the connection details in the %v file.\n", configFile)
	if config.Inbounds.Hg != nil || len(config.Outbounds) != 0 {
		_, _ = fmt.Fprintln(tw, `Passwords for Shadowsocks, Trojan, NaiveProxy, and SunnyQUIC are derived from
the "password" field. Use the passwords below when configuring other clients.`)
	}

	_, _ = fmt.Fprintln(tw, "\nInbounds:")
	httpSOCKS := config.Inbounds.HTTPSOCKS
	// Only HTTP/SOCKS can be set as the system proxy, so the SYSTEM PROXY
	// column is shown only along with it.
	printInfoHeader(tw, httpSOCKS != nil)
	if httpSOCKS != nil {
		systemProxy := "off"
		if httpSOCKS.SystemProxy {
			systemProxy = "on"
		}
		printInfoRows(tw, "http-socks", httpSOCKS.Host,
			[]protocolInfo{{"HTTP/SOCKS", "TCP", httpSOCKS.Port, httpSOCKS.Username, httpSOCKS.Password}},
			systemProxy)
	}
	hg := config.Inbounds.Hg
	if hg != nil {
		hgSystemProxy := ""
		if httpSOCKS != nil {
			hgSystemProxy = "-"
		}
		printInfoRows(tw, "hg", hg.Host,
			carrierInfos(hg.Password, hg.TCPPort, hg.TLSPort, hg.QUICPort),
			hgSystemProxy)
	}

	if len(config.Outbounds) != 0 {
		_, _ = fmt.Fprintln(tw, "\nOutbounds:")
		printInfoHeader(tw, false)
		for _, name := range slices.Sorted(maps.Keys(config.Outbounds)) {
			node := config.Outbounds[name]
			printInfoRows(tw, name, node.Host,
				carrierInfos(node.Password, node.TCPPort, node.TLSPort, node.QUICPort),
				"")
		}
	}

	if config.Misc.Profiling {
		_, _ = fmt.Fprintln(tw, "\nMisc:")
		_, _ = fmt.Fprintf(tw, "  profiling-port\t%v\n", config.Misc.ProfilingPort)
	}
	_ = tw.Flush()
}

func printInfoHeader(w io.Writer, systemProxyColumn bool) {
	header := "  NAME\tHOST\tPROTOCOL\tNETWORK\tPORT\tUSERNAME\tPASSWORD"
	if systemProxyColumn {
		header += "\tSYSTEM PROXY"
	}
	_, _ = fmt.Fprintln(w, header)
}

// printInfoRows prints a row for each of infos, with name and host only on the
// first row because they are the same for all of them. systemProxy is printed
// in the SYSTEM PROXY column for http-socks inbound.
func printInfoRows(w io.Writer, name string, host string, infos []protocolInfo, systemProxy string) {
	for i, info := range infos {
		if i > 0 {
			name, host = "", ""
		}
		_, _ = fmt.Fprintf(w, "  %v\t%v\t%v\t%v\t%v\t%v\t%v",
			name, host, info.protocol, info.network, info.port, info.username, info.password)
		if systemProxy != "" {
			_, _ = fmt.Fprintf(w, "\t%v", systemProxy)
		}
		_, _ = fmt.Fprintln(w)
	}
}

// carrierInfos returns the info of every carrier protocol that a hg server
// with these settings accepts. Shadowsocks is accepted only when tcpPort is
// set.
func carrierInfos(password *conf.Password, tcpPort *uint16, tlsPort, quicPort uint16) []protocolInfo {
	var infos []protocolInfo
	if tcpPort != nil {
		infos = append(infos, protocolInfo{
			"Shadowsocks (" + ss_carrier.Method + ")", "TCP", *tcpPort, "-", ss_carrier.AuthPassword(password),
		})
	}
	return append(infos,
		protocolInfo{"Trojan", "TLS (over TCP)", tlsPort, "-", tr_carrier.AuthPassword(password)},
		protocolInfo{"NaiveProxy (HTTP/2)", "TLS (over TCP)", tlsPort, passwordutil.DefaultUsername, np_carrier.AuthPassword(password)},
		protocolInfo{"SunnyQUIC", "QUIC (over UDP)", quicPort, passwordutil.DefaultUsername, sq_carrier.AuthPassword(password)},
	)
}
