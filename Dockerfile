FROM node:22-slim AS base
LABEL org.opencontainers.image.source="https://github.com/docmost/docmost"

RUN npm install -g pnpm@10.4.0

FROM base AS builder

WORKDIR /app

# Copy dependency manifests and config (cache layer when only source changes)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc nx.json ./
COPY patches/ patches/
COPY apps/server/package.json apps/server/
COPY apps/client/package.json apps/client/
COPY packages/editor-ext/package.json packages/editor-ext/

RUN pnpm install --frozen-lockfile

# NOTE: We run per-project builds (not a single "pnpm build") so Docker can cache each app/package
# independently. If the root "build" script in package.json changes (e.g. new project or different
# targets), update this Dockerfile to match: add/remove/reorder COPY + nx run steps below, and
# update the installer stage COPY --from=builder for any new apps/packages.
# Current mapping: package.json "build" = nx run-many -t build → editor-ext, client, server.

# Build editor-ext first (client depends on it); only this layer invalidates when editor-ext changes
COPY packages/editor-ext/ packages/editor-ext/
RUN pnpm exec nx run @docmost/editor-ext:build

# Build client; only this layer invalidates when client changes
COPY apps/client/ apps/client/
RUN pnpm exec nx run client:build

# Build server; only this layer invalidates when server changes
COPY apps/server/ apps/server/
RUN pnpm exec nx run server:build

FROM base AS installer

RUN apt-get update \
  && apt-get install -y --no-install-recommends curl bash \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy apps (keep in sync with builder stage: add dist + package.json for any new app)
COPY --from=builder /app/apps/server/dist /app/apps/server/dist
COPY --from=builder /app/apps/client/dist /app/apps/client/dist
COPY --from=builder /app/apps/server/package.json /app/apps/server/package.json

# Copy packages (keep in sync with builder stage: add dist + package.json for any new package)
COPY --from=builder /app/packages/editor-ext/dist /app/packages/editor-ext/dist
COPY --from=builder /app/packages/editor-ext/package.json /app/packages/editor-ext/package.json

# Copy root package files
COPY --from=builder /app/package.json /app/package.json
COPY --from=builder /app/pnpm*.yaml /app/
COPY --from=builder /app/.npmrc /app/.npmrc

# Copy patches
COPY --from=builder /app/patches /app/patches

RUN chown -R node:node /app

USER node

RUN pnpm install --frozen-lockfile --prod

RUN mkdir -p /app/data/storage

VOLUME ["/app/data/storage"]

EXPOSE 3000

CMD ["pnpm", "start"]
