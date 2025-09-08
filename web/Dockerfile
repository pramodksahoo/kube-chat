# Secure Production Nginx build for KubeChat Web Frontend
# Runs as non-root user on port 8080 with proper permissions

FROM nginx:1.25-alpine AS production

# Image metadata
LABEL org.opencontainers.image.title="KubeChat Web Frontend"
LABEL org.opencontainers.image.description="KubeChat Phase 1 Model 1 Web Frontend"
LABEL org.opencontainers.image.version="${VERSION:-dev}"
LABEL org.opencontainers.image.vendor="KubeChat"
LABEL org.opencontainers.image.source="https://github.com/pramodksahoo/kube-chat"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install additional packages for security
RUN apk add --no-cache \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S kubechat \
    && adduser -S kubechat -u 1001

# Create secure nginx configuration that runs as non-root
COPY <<EOF /etc/nginx/nginx.conf
worker_processes auto;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Use /tmp for temporary files (writable by non-root)
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;

    # Log to stdout/stderr for container best practices
    access_log /dev/stdout;

    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 16M;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' ws: wss:;" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    server {
        listen 8083;
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html;

        # Security: Hide nginx version
        server_tokens off;

        # Handle React Router
        location / {
            try_files \$uri \$uri/ /index.html;
        }

        # API proxy configuration - will use environment variable substitution
        location /api/ {
            proxy_pass http://kubechat-dev-api-gateway:8080/;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # WebSocket support for real-time features
        location /ws/ {
            proxy_pass http://kubechat-dev-api-gateway:8080/ws/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # Static assets caching
        location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\\n";
            add_header Content-Type text/plain;
        }

        # Security: Deny access to sensitive files
        location ~ /\\\\. {
            deny all;
        }

        # Error pages
        error_page 404 /index.html;
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
}
EOF

# Copy pre-built application from build context
COPY web/dist /usr/share/nginx/html

# Set proper permissions for non-root user
RUN chown -R kubechat:kubechat /usr/share/nginx/html \
    && chmod -R 755 /usr/share/nginx/html \
    && chown -R kubechat:kubechat /var/cache/nginx \
    && chown -R kubechat:kubechat /var/log/nginx \
    && chown kubechat:kubechat /etc/nginx/nginx.conf \
    && chmod 644 /etc/nginx/nginx.conf

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8083/health || exit 1

# Expose non-privileged port
EXPOSE 8083

# Run as non-root user
USER kubechat

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]