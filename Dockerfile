FROM node:24.15.0-trixie-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN npm ci && npm pack --pack-destination /tmp

FROM node:24.15.0-trixie-slim
COPY --from=builder /tmp/nightshade-compact-0.1.1.tgz /tmp/nightshade.tgz
RUN npm install --global /tmp/nightshade.tgz && rm /tmp/nightshade.tgz
WORKDIR /project
ENTRYPOINT ["nightshade"]
