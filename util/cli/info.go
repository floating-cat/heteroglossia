package cli

import (
	"cmp"
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
	hg := config.Inbounds.Hg
	// Only hg has a "host" field in inbounds, and only HTTP/SOCKS can be set
	// as the system proxy, so the HOST and SYSTEM PROXY columns are shown only
	// along with them in inbounds header.
	inboundColumns := extraColumns{host: hg != nil, listenHost: true, systemProxy: httpSOCKS != nil}
	printInfoHeader(tw, inboundColumns)
	if httpSOCKS != nil {
		systemProxy := "off"
		if httpSOCKS.SystemProxy {
			systemProxy = "on"
		}
		// "*" is used in the LISTEN HOST column when it listens on all interfaces.
		printInfoRows(tw, inboundColumns, "http-socks", "-", cmp.Or(httpSOCKS.ListenHost, "*"),
			[]protocolInfo{{"HTTP/SOCKS", "TCP", httpSOCKS.Port, httpSOCKS.Username, httpSOCKS.Password}},
			systemProxy)
	}
	if hg != nil {
		printInfoRows(tw, inboundColumns, "hg", hg.Host, cmp.Or(hg.ListenHost, "*"),
			carrierInfos(hg.Password, hg.TCPPort, hg.TLSPort, hg.QUICPort),
			"-")
	}

	if len(config.Outbounds) != 0 {
		_, _ = fmt.Fprintln(tw, "\nOutbounds:")
		outboundColumns := extraColumns{host: true}
		printInfoHeader(tw, outboundColumns)
		for _, name := range slices.Sorted(maps.Keys(config.Outbounds)) {
			node := config.Outbounds[name]
			printInfoRows(tw, outboundColumns, name, node.Host, "",
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

type extraColumns struct {
	host        bool
	listenHost  bool
	systemProxy bool
}

func printInfoHeader(w io.Writer, columns extraColumns) {
	header := "  NAME"
	if columns.host {
		header += "\tHOST"
	}
	if columns.listenHost {
		header += "\tLISTEN HOST"
	}
	header += "\tPROTOCOL\tNETWORK\tPORT\tUSERNAME\tPASSWORD"
	if columns.systemProxy {
		header += "\tSYSTEM PROXY"
	}
	_, _ = fmt.Fprintln(w, header)
}

// printInfoRows prints a row for each of infos, with name, host, and listenHost
// only on the first row because they are the same for all of them. Only the
// columns in columns are printed, so the rows match the header printed by
// printInfoHeader with the same columns.
func printInfoRows(w io.Writer, columns extraColumns, name, host, listenHost string,
	infos []protocolInfo, systemProxy string) {
	for i, info := range infos {
		if i > 0 {
			name, host, listenHost = "", "", ""
		}
		_, _ = fmt.Fprintf(w, "  %v", name)
		if columns.host {
			_, _ = fmt.Fprintf(w, "\t%v", host)
		}
		if columns.listenHost {
			_, _ = fmt.Fprintf(w, "\t%v", listenHost)
		}
		_, _ = fmt.Fprintf(w, "\t%v\t%v\t%v\t%v\t%v",
			info.protocol, info.network, info.port, info.username, info.password)
		if columns.systemProxy {
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
