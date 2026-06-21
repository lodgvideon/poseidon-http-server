{{/*
Expand the name of the chart.
*/}}
{{- define "poseidon-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec).
*/}}
{{- define "poseidon-server.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "poseidon-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "poseidon-server.labels" -}}
helm.sh/chart: {{ include "poseidon-server.chart" . }}
{{ include "poseidon-server.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "poseidon-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "poseidon-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The image reference (repository:tag), defaulting tag to the chart appVersion.
*/}}
{{- define "poseidon-server.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "poseidon-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "poseidon-server.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Render a probe action block based on .Values.probes.type. Used by both the
liveness and readiness probes so they stay consistent. Callers must NOT use
httpGet against the h2c port — see values.yaml PROBES note.
*/}}
{{- define "poseidon-server.probeAction" -}}
{{- if eq .Values.probes.type "grpc" -}}
grpc:
  port: {{ .Values.probes.grpc.port }}
  {{- if .Values.probes.grpc.service }}
  service: {{ .Values.probes.grpc.service | quote }}
  {{- end }}
{{- else -}}
tcpSocket:
  port: {{ .Values.container.port }}
{{- end -}}
{{- end }}
