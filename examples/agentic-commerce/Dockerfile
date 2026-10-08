# The demo runs from source: tsx is a devDependency used at runtime, and the
# independent verification controls (V, and the ledger scripts) shell out to
# python3. So this image keeps dev dependencies and ships a Python runtime.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first, so a source-only change reuses this layer.
COPY package.json package-lock.json ./
RUN npm ci --include=dev

COPY . .

# One image, two roles. SERVICE_ROLE picks the npm script, so the merchant edge
# (4949) and the Responsible Party hub (4950) deploy from the same build rather
# than diverging into two images or two per-service start commands.
# BIND_HOST must leave loopback for the platform to reach the listener.
ENV NODE_ENV=production \
    BIND_HOST=0.0.0.0 \
    SERVICE_ROLE=merchant

CMD ["sh", "-c", "npm run \"$SERVICE_ROLE\""]
