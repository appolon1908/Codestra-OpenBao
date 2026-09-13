{{- with secret "__SECRET_API_PATH__" -}}
{{ .Data.data.payload }}
{{- end -}}
