{{/*
Expand the name of the chart.
*/}}
{{- define "gov-jwks-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a fully qualified app name. Capped at 63 characters per DNS label rules.
*/}}
{{- define "gov-jwks-service.fullname" -}}
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
{{- define "gov-jwks-service.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every resource.
*/}}
{{- define "gov-jwks-service.labels" -}}
helm.sh/chart: {{ include "gov-jwks-service.chart" . }}
{{ include "gov-jwks-service.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: gov-jwks-service
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Selector labels (must remain stable across upgrades).
*/}}
{{- define "gov-jwks-service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gov-jwks-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Server-specific names, labels, and selectors.
*/}}
{{- define "gov-jwks-service.server.fullname" -}}
{{- printf "%s-server" (include "gov-jwks-service.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gov-jwks-service.server.labels" -}}
{{ include "gov-jwks-service.labels" . }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "gov-jwks-service.server.selectorLabels" -}}
{{ include "gov-jwks-service.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "gov-jwks-service.server.serviceAccountName" -}}
{{- if .Values.server.serviceAccount.create -}}
{{- default (include "gov-jwks-service.server.fullname" .) .Values.server.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.server.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Whether the HorizontalPodAutoscaler should be installed. Requires autoscaling
to be enabled and both replica bounds to exceed 1 — an HPA with a 1/1 range
cannot scale and would only pin the Deployment to a single replica.
Returns the string "true" when enabled, empty otherwise.
*/}}
{{- define "gov-jwks-service.server.hpaEnabled" -}}
{{- if and .Values.server.autoscaling.enabled (gt (int .Values.server.autoscaling.minReplicas) 1) (gt (int .Values.server.autoscaling.maxReplicas) 1) -}}
true
{{- end -}}
{{- end -}}

{{/*
Whether the PodDisruptionBudget should be installed. Only meaningful when more
than one server pod can exist — either the HPA is installed (and can scale past
one replica) or a static replicaCount above 1 is requested. A PDB over a single
pod would block voluntary disruptions (node drains) indefinitely.
Returns the string "true" when enabled, empty otherwise.
*/}}
{{- define "gov-jwks-service.server.pdbEnabled" -}}
{{- if and .Values.server.podDisruptionBudget.enabled (or (eq (include "gov-jwks-service.server.hpaEnabled" .) "true") (gt (int .Values.server.replicaCount) 1)) -}}
true
{{- end -}}
{{- end -}}

{{/*
Rotator-specific names, labels, and selectors.
*/}}
{{- define "gov-jwks-service.rotator.fullname" -}}
{{- printf "%s-rotator" (include "gov-jwks-service.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gov-jwks-service.rotator.labels" -}}
{{ include "gov-jwks-service.labels" . }}
app.kubernetes.io/component: rotator
{{- end -}}

{{- define "gov-jwks-service.rotator.selectorLabels" -}}
{{ include "gov-jwks-service.selectorLabels" . }}
app.kubernetes.io/component: rotator
{{- end -}}

{{- define "gov-jwks-service.rotator.serviceAccountName" -}}
{{- if .Values.rotator.serviceAccount.create -}}
{{- default (include "gov-jwks-service.rotator.fullname" .) .Values.rotator.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.rotator.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image references — fall back to .Chart.AppVersion when tag is empty.
*/}}
{{- define "gov-jwks-service.server.image" -}}
{{- $tag := default .Chart.AppVersion .Values.server.image.tag -}}
{{- printf "%s:%s" .Values.server.image.repository $tag -}}
{{- end -}}

{{- define "gov-jwks-service.rotator.image" -}}
{{- $tag := default .Chart.AppVersion .Values.rotator.image.tag -}}
{{- printf "%s:%s" .Values.rotator.image.repository $tag -}}
{{- end -}}

{{/*
Common Vault env block reused by both server and rotator.
Usage: {{ include "gov-jwks-service.vaultEnv" (dict "ctx" . "k8sRole" "jwks-service") }}
*/}}
{{- define "gov-jwks-service.vaultEnv" -}}
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

{{/*
Has the chart been configured with additional trusted CA roots?
*/}}
{{- define "gov-jwks-service.trustedCAsEnabled" -}}
{{- if or .Values.trustedCAs.bundles .Values.trustedCAs.existingSecret -}}true{{- end -}}
{{- end -}}

{{/*
Resolve the Secret name that holds the trusted-CA bundles. Returns
existingSecret when set, otherwise the chart-managed secret name. Empty
when no CA roots are configured.
*/}}
{{- define "gov-jwks-service.trustedCAsSecretName" -}}
{{- if .Values.trustedCAs.existingSecret -}}
{{- .Values.trustedCAs.existingSecret -}}
{{- else if .Values.trustedCAs.bundles -}}
{{- printf "%s-trusted-cas" (include "gov-jwks-service.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Env block that points the Go runtime at the additional CA directory.
SSL_CERT_DIR adds to the default trust store; SSL_CERT_FILE remains unset
so distroless's bundled /etc/ssl/certs/ca-certificates.crt continues to load.
*/}}
{{- define "gov-jwks-service.trustedCAsEnv" -}}
{{- if eq (include "gov-jwks-service.trustedCAsEnabled" .) "true" }}
- name: SSL_CERT_DIR
  value: {{ .Values.trustedCAs.mountPath | quote }}
{{- end }}
{{- end -}}

{{/*
Volume entry for the trusted-CA Secret. Each Secret key becomes a file in
the mounted directory; Go reads every file in the dir as PEM.
*/}}
{{- define "gov-jwks-service.trustedCAsVolume" -}}
{{- if eq (include "gov-jwks-service.trustedCAsEnabled" .) "true" }}
- name: trusted-cas
  secret:
    secretName: {{ include "gov-jwks-service.trustedCAsSecretName" . }}
{{- end }}
{{- end -}}

{{/*
Volume mount entry for the trusted CAs. Read-only, fits
readOnlyRootFilesystem: true.
*/}}
{{- define "gov-jwks-service.trustedCAsVolumeMount" -}}
{{- if eq (include "gov-jwks-service.trustedCAsEnabled" .) "true" }}
- name: trusted-cas
  mountPath: {{ .Values.trustedCAs.mountPath | quote }}
  readOnly: true
{{- end }}
{{- end -}}

{{/*
Checksum of the trusted-CAs configuration. Used as a pod annotation to
force a rolling restart when CA roots change. For existingSecret the user
must trigger restarts themselves (e.g. via stakater/Reloader).
*/}}
{{- define "gov-jwks-service.trustedCAsChecksum" -}}
{{- $t := .Values.trustedCAs -}}
{{- printf "bundles=%s|existing=%s|path=%s" (toJson $t.bundles) $t.existingSecret $t.mountPath | sha256sum -}}
{{- end -}}
