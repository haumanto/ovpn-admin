{{- range $server := .Hosts }}
remote {{ $server.Host }} {{ $server.Port }} {{ $server.Protocol }}
{{- end }}

verb 3
client
nobind
dev tun
# AEAD cipher list, negotiated with the server (OpenVPN 2.5+); the server accepts these three and nothing else
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth-nocache
key-direction 1
#redirect-gateway def1
# if the server has IPv6 enabled, use this line instead to route IPv6 traffic as well
#redirect-gateway def1 ipv6
tls-client
remote-cert-tls server
# uncomment below lines for use with linux
#script-security 2
# if you use resolved
#up /etc/openvpn/update-resolv-conf
#down /etc/openvpn/update-resolv-conf
# if you use systemd-resolved first install openvpn-systemd-resolved package
#up /etc/openvpn/update-systemd-resolved
#down /etc/openvpn/update-systemd-resolved

{{- if .PasswdAuth }}
auth-user-pass
{{- end }}

<cert>
{{ .Cert -}}
</cert>
<key>
{{ .Key -}}
</key>
<ca>
{{ .CA -}}
</ca>
<tls-auth>
{{ .TLS -}}
</tls-auth>
