{{/*
Expand the name of the chart.
*/}}
{{- define "jwks-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a fully qualified app name. Capped at 63 characters per DNS label rules.
*/}}
{{- define "jwks-service.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label.
*/}}
{{- define "jwks-service.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every resource.
*/}}
{{- define "jwks-service.labels" -}}
helm.sh/chart: {{ include "jwks-service.chart" . }}
{{ include "jwks-service.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: jwks-service
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Selector labels (must remain stable across upgrades).
*/}}
{{- define "jwks-service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jwks-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Server-specific names, labels, and selectors.
*/}}
{{- define "jwks-service.server.fullname" -}}
{{- printf "%s-server" (include "jwks-service.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "jwks-service.server.labels" -}}
{{ include "jwks-service.labels" . }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "jwks-service.server.selectorLabels" -}}
{{ include "jwks-service.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "jwks-service.server.serviceAccountName" -}}
{{- if .Values.server.serviceAccount.create -}}
{{- default (include "jwks-service.server.fullname" .) .Values.server.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.server.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Rotator-specific names, labels, and selectors.
*/}}
{{- define "jwks-service.rotator.fullname" -}}
{{- printf "%s-rotator" (include "jwks-service.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "jwks-service.rotator.labels" -}}
{{ include "jwks-service.labels" . }}
app.kubernetes.io/component: rotator
{{- end -}}

{{- define "jwks-service.rotator.selectorLabels" -}}
{{ include "jwks-service.selectorLabels" . }}
app.kubernetes.io/component: rotator
{{- end -}}

{{- define "jwks-service.rotator.serviceAccountName" -}}
{{- if .Values.rotator.serviceAccount.create -}}
{{- default (include "jwks-service.rotator.fullname" .) .Values.rotator.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.rotator.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image references — fall back to .Chart.AppVersion when tag is empty.
*/}}
{{- define "jwks-service.server.image" -}}
{{- $tag := default .Chart.AppVersion .Values.server.image.tag -}}
{{- printf "%s:%s" .Values.server.image.repository $tag -}}
{{- end -}}

{{- define "jwks-service.rotator.image" -}}
{{- $tag := default .Chart.AppVersion .Values.rotator.image.tag -}}
{{- printf "%s:%s" .Values.rotator.image.repository $tag -}}
{{- end -}}

{{/*
Common Vault env block reused by both server and rotator.
Usage: {{ include "jwks-service.vaultEnv" (dict "ctx" . "k8sRole" "jwks-service") }}
*/}}
{{- define "jwks-service.vaultEnv" -}}
- name: VAULT_ADDR
  value: {{ .ctx.Values.vault.addr | quote }}
- name: VAULT_K8S_ROLE
  value: {{ .k8sRole | quote }}
- name: VAULT_K8S_MOUNT
  value: {{ .ctx.Values.vault.k8sMount | quote }}
- name: VAULT_MOUNT
  value: {{ .ctx.Values.vault.mount | quote }}
- name: VAULT_SECRET_PATH
  value: {{ .ctx.Values.vault.secretPath | quote }}
{{- end -}}
