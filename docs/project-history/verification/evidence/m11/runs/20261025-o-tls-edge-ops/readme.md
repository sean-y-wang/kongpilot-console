# O-tls-edge — ops evidence（非 UI 截图）
产品 TLS edge 由 nginx 配置（`deploy/nginx/console-production.conf`）提供，无控制台界面。本目录为 2026-10-25 lab 实测（kp009-tls-console-edge，host network，read_only，cap_drop=ALL，非生产自签 SAN `oauth.evidence.local`）：
- `openssl-tls13.txt`：TLSv1.3 / TLS_AES_256_GCM_SHA384 握手成功（自签，非生产证书）。
- `openssl-tls11-reject.txt`：TLSv1.1 被拒（exit=1）。
- `https-headers.txt`：HTTPS 200 + HSTS/CSP 响应头；`http-healthz.txt`：明文 healthz。
- `nginx-T-excerpt.txt`：运行中 `nginx -T` 的 listen/ssl_protocols/tickets off/HSTS/CSP。
限制：非生产证书/域名；生产证书与公网入口需部署现场验证。commercialClosed=false。
