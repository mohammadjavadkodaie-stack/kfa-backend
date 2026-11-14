# syntax=docker/dockerfile:1
FROM node:24-alpine AS base
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable
WORKDIR /app

FROM base AS build
COPY package.json pnpm-lock.yaml ./
RUN corepack prepare pnpm@12.14.0 --activate && pnpm install --frozen-lockfile
COPY prisma ./prisma
RUN pnpm exec prisma generate
COPY tsconfig*.json ./
COPY src ./src
RUN pnpm build
RUN pnpm prune --prod

FROM node:24-alpine AS runtime
ENV NODE_ENV=production
ENV PORT=3001
WORKDIR /app
RUN addgroup -S -g 10001 kfa && adduser -S -D -H -u 10001 -G kfa kfa
COPY --from=build --chown=kfa:kfa /app/dist ./dist
COPY --from=build --chown=kfa:kfa /app/node_modules ./node_modules
COPY --from=build --chown=kfa:kfa /app/prisma ./prisma
COPY --from=build --chown=kfa:kfa /app/package.json ./package.json
USER kfa
EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD wget -q -O - http://127.0.0.1:3001/health || exit 1
CMD ["node", "dist/main.js"]

# Migrations are deliberately separate from app startup:
# docker compose --env-file deploy/.env.production --profile tools run --rm migrate
