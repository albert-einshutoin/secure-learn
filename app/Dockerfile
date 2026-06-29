FROM node:26-alpine AS deps

WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM deps AS build

COPY . .
RUN npm run build
RUN npm prune --omit=dev

FROM node:26-alpine AS runner

WORKDIR /app

RUN addgroup -g 10001 -S appgroup \
  && adduser -S appuser -u 10001 -G appgroup \
  && mkdir -p /var/log/app \
  && chown -R appuser:appgroup /app /var/log/app

COPY --from=build --chown=appuser:appgroup /app/package.json ./package.json
COPY --from=build --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=build --chown=appuser:appgroup /app/dist ./dist
COPY --from=build --chown=appuser:appgroup /app/public ./public

ENV NODE_ENV=production
ENV PUBLIC_DIR=/app/public

EXPOSE 3000

USER appuser

CMD ["node", "dist/main.js"]
