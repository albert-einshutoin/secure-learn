FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS deps

WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM deps AS build

COPY . .
RUN npm run build
RUN npm prune --omit=dev

FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS runner

WORKDIR /app

RUN apk add --no-cache su-exec \
  && addgroup -g 10001 -S appgroup \
  && adduser -S appuser -u 10001 -G appgroup \
  && mkdir -p /var/log/app \
  && chown -R appuser:appgroup /app /var/log/app

COPY --chown=root:root docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh

COPY --from=build --chown=appuser:appgroup /app/package.json ./package.json
COPY --from=build --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=build --chown=appuser:appgroup /app/dist ./dist
COPY --from=build --chown=appuser:appgroup /app/public ./public

ENV NODE_ENV=production
ENV PUBLIC_DIR=/app/public

EXPOSE 3000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "dist/main.js"]
