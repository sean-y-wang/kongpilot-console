# syntax=docker/dockerfile:1
FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c
LABEL org.opencontainers.image.title="KongPilot Metrics Collector" org.opencontainers.image.description="Kong 网关管理平台"
ENV PATH=/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /opt/kongos-collector
COPY --chown=1000:1000 deploy/metrics-collector/*.mjs ./
USER 1000:1000
ENTRYPOINT []
EXPOSE 9093
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 CMD node -e "fetch('http://127.0.0.1:9093/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "server.mjs"]
