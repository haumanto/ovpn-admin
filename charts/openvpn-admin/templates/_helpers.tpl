{{/*
IP family settings of the Services: PreferDualStack when openvpn.dualStack is enabled.
*/}}
{{- define "openvpn-admin.ipFamilies" -}}
{{- if .Values.openvpn.dualStack }}
ipFamilyPolicy: PreferDualStack
{{- with .Values.openvpn.ipFamilies }}
ipFamilies:
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}
{{- end }}

{{/*
External IPs for inlet: ExternalIP (openvpn.externalIPs + legacy openvpn.externalIP) as a JSON array.
*/}}
{{- define "openvpn-admin.externalIPs" -}}
{{- $ips := list }}
{{- range .Values.openvpn.externalIPs }}
{{- $ips = append $ips (toString .) }}
{{- end }}
{{- with .Values.openvpn.externalIP }}
{{- $ips = append $ips (toString .) }}
{{- end }}
{{- if not $ips }}
{{- fail "openvpn.externalIPs (or the legacy openvpn.externalIP) is required for inlet: ExternalIP" }}
{{- end }}
{{- uniq $ips | toJson }}
{{- end }}

{{/*
Port of the OpenVPN server for the clients: openvpn.externalPort, else hostPort for inlet: HostPort, else 1194.
*/}}
{{- define "openvpn-admin.externalPort" -}}
{{- $port := 1194 }}
{{- if and (eq (toString .Values.openvpn.inlet) "HostPort") .Values.openvpn.hostPort }}
{{- $port = .Values.openvpn.hostPort }}
{{- end }}
{{- with .Values.openvpn.externalPort }}
{{- $port = . }}
{{- end }}
{{- $port }}
{{- end }}

{{/*
Fails unless admin credentials are set and are not the old built-in defaults (admin/changeme).
*/}}
{{- define "openvpn-admin.validateBasicAuth" -}}
{{- $user := .Values.ingress.basicAuth.user | default "" | toString }}
{{- $password := .Values.ingress.basicAuth.password | default "" | toString }}
{{- if or (not $user) (not $password) }}
{{- fail "ingress.basicAuth.user and ingress.basicAuth.password are required: the admin UI must not run without credentials (set them with --set or a values file kept out of git)" }}
{{- end }}
{{- if or (eq $password "changeme") (and (eq $user "admin") (eq $password "changeme")) }}
{{- fail "ingress.basicAuth uses the built-in default password \"changeme\": set your own ingress.basicAuth.user and ingress.basicAuth.password" }}
{{- end }}
{{- end }}

{{/*
Image tag: the explicit tag value, else the chart appVersion. Never master.
*/}}
{{- define "openvpn-admin.imageTag" -}}
{{- $tag := (.tag | default "" | toString) | default .appVersion }}
{{- if eq $tag "master" }}
{{- fail "image tag \"master\" is not allowed, use a release tag (default: the appVersion of the chart)" }}
{{- end }}
{{- $tag }}
{{- end }}
