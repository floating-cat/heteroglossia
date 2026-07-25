# Notes

## Protocol Implementation Limitations

### SOCKS inbound

It doesn't support SOCKS4 or UDP for SOCKS inbound.

### Shadowsocks carrier

It supports Shadowsocks 2022, but it doesn't support UDP, the
"2022-blake3-aes-256-gcm" method, or the "Shadowsocks 2022 Extensible
Identity Headers" specification.

### Trojan carrier

It doesn't support UDP.

### SunnyQUIC carrier

It doesn't support UDP.

## Protocol Design Limitations

### Shadowsocks 2022 carrier

The client's system time cannot differ from the server's by more than 30 seconds.

## OS-Level Limitations

### KDE

If you configure an IPv6 address with credentials for HTTP inbound, hg
won't be able to configure this as a system proxy due to a KDE bug.

## Application-Level Limitations

### Firefox

If you use Firefox with the system proxy, open the `about:config` page and
set `network.proxy.default_pac_script_socks_version` to `5`, because hg
doesn't support SOCKS4. You can also set `network.proxy.socks_remote_dns` to
`true` for better security.

## Optimizations

### Enable BBR on a Linux Server for TCP

```sh
sudo su
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/bbr.conf
modprobe tcp_bbr
sysctl -p /etc/sysctl.d/bbr.conf
```

### Increase UDP Buffer Sizes on Both the QUIC Server and Client

Check https://quic-go.net/docs/quic/optimizations/#udp-buffer-sizes
