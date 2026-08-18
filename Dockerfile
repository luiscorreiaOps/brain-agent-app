FROM grafana/grafana:12.3.1@sha256:2175aaa91c96733d86d31cf270d5310b278654b03f5718c59de12a865380a31f

COPY dist/ /var/lib/grafana/plugins/brain-agent/
