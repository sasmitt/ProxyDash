# ProxyCheck — production image (zero runtime dependencies)
FROM node:20-alpine

LABEL maintainer="Diwas Khatri"

WORKDIR /app
ENV NODE_ENV=production

# Install only what exists in the repo (no network fetch of packages needed)
COPY package.json server.js ./
COPY src ./src
COPY public ./public

RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app
USER app

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD node -e "require('http').get('http://127.0.0.1:' + (process.env.PORT || 3000) + '/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
