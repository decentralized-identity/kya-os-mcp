#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ── Colours ──────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

PIDS=()
cleanup() {
  echo ""
  echo -e "${DIM}Shutting down example servers...${NC}"
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo -e "${GREEN}Done.${NC}"
}
trap cleanup EXIT INT TERM

usage() {
  echo -e "${BOLD}Usage:${NC} $0 [options] [example...]"
  echo ""
  echo "Start KYA-OS example servers for testing with the MCP Inspector."
  echo ""
  echo -e "${BOLD}Examples:${NC}"
  echo "  $0                    # start all examples"
  echo "  $0 consent-basic      # start just consent-basic"
  echo "  $0 consent-basic node-server"
  echo "  $0 --no-inspector     # start servers without opening Inspector"
  echo ""
  echo -e "${BOLD}Available examples:${NC}"
  echo "  node-server        Low-level KYA-OS server with proof + restricted tools"
  echo "  consent-basic      Human-in-the-loop consent flow (built-in UI)"
  echo "  consent-full       Consent flow with @kya-os/consent (production UI)"
  echo "  consent-persistence Durable consent: two instances share a file-backed grant store"
  echo "  context7-with-kya-os Context7 MCP server + KYA-OS identity"
  echo ""
  exit 0
}

# ── Parse args ───────────────────────────────────────────────────────
OPEN_INSPECTOR=true
REQUESTED=()

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage ;;
    --no-inspector) OPEN_INSPECTOR=false ;;
    *) REQUESTED+=("$arg") ;;
  esac
done

ALL_EXAMPLES=(node-server consent-basic consent-full consent-persistence context7-with-kya-os)

if [ ${#REQUESTED[@]} -eq 0 ]; then
  EXAMPLES=("${ALL_EXAMPLES[@]}")
else
  EXAMPLES=("${REQUESTED[@]}")
  for ex in "${EXAMPLES[@]}"; do
    if [[ ! " ${ALL_EXAMPLES[*]} " =~ " ${ex} " ]]; then
      echo -e "${RED}Unknown example: ${ex}${NC}"
      echo "Available: ${ALL_EXAMPLES[*]}"
      exit 1
    fi
  done
fi

# ── Install deps ─────────────────────────────────────────────────────
echo -e "${BOLD}Installing dependencies...${NC}"

if [ ! -d "$ROOT/node_modules" ]; then
  echo -e "${DIM}  root${NC}"
  npm install --silent 2>/dev/null
fi

for ex in "${EXAMPLES[@]}"; do
  dir="$ROOT/examples/$ex"
  [ -f "$dir/package.json" ] || continue

  # (Re)install when node_modules is missing OR the linked @kya-os/mcp dep is
  # stale/broken — the latter causes a confusing ERR_MODULE_NOT_FOUND at start
  # even though deps are unchanged. `-e` follows the file: symlink to its target.
  needs_install=false
  if [ ! -d "$dir/node_modules" ]; then
    needs_install=true
  elif grep -q '"@kya-os/mcp"' "$dir/package.json" \
       && [ ! -e "$dir/node_modules/@kya-os/mcp/package.json" ]; then
    echo -e "${YELLOW}  $ex: @kya-os/mcp link is stale — reinstalling${NC}"
    needs_install=true
  fi

  if [ "$needs_install" = true ]; then
    echo -e "${DIM}  $ex${NC}"
    if [ -f "$dir/pnpm-lock.yaml" ]; then
      (cd "$dir" && pnpm install --silent 2>/dev/null) || (cd "$dir" && npm install --silent 2>/dev/null)
    else
      (cd "$dir" && npm install --silent 2>/dev/null)
    fi
  fi
done

echo -e "${GREEN}Dependencies ready.${NC}"
echo ""

# ── Start servers ────────────────────────────────────────────────────
# Parallel indexed arrays (bash 3 compatible – no associative arrays)
EX_NAMES=()
EX_URLS=()
EX_TRANSPORTS=()

start_example() {
  local name="$1"
  EX_NAMES+=("$name")
  case "$name" in
    node-server)
      PORT=3001 CONSENT_PORT=3011 npx tsx examples/node-server/server.ts &
      PIDS+=($!)
      EX_URLS+=("http://localhost:3001/sse")
      EX_TRANSPORTS+=("SSE")
      ;;
    consent-basic)
      PORT=3002 CONSENT_PORT=3012 npx tsx examples/consent-basic/src/server.ts &
      PIDS+=($!)
      EX_URLS+=("http://localhost:3002/sse")
      EX_TRANSPORTS+=("SSE")
      ;;
    consent-full)
      PORT=3003 CONSENT_PORT=3013 npx tsx examples/consent-full/src/server.ts &
      PIDS+=($!)
      EX_URLS+=("http://localhost:3003/sse")
      EX_TRANSPORTS+=("SSE")
      ;;
    consent-persistence)
      PORT_A=3005 PORT_B=3006 CONSENT_PORT=3015 npx tsx examples/consent-persistence/src/server.ts &
      PIDS+=($!)
      EX_URLS+=("http://localhost:3005/mcp")
      EX_TRANSPORTS+=("Streamable HTTP")
      ;;
    context7-with-kya-os)
      npx tsx examples/context7-with-kya-os/src/index.ts --transport http --port 3004 &
      PIDS+=($!)
      EX_URLS+=("http://localhost:3004/mcp")
      EX_TRANSPORTS+=("Streamable HTTP")
      ;;
  esac
}

for ex in "${EXAMPLES[@]}"; do
  start_example "$ex"
done

sleep 2

# ── Print summary ────────────────────────────────────────────────────
echo -e "${BOLD}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}│  KYA-OS Example Servers                                        │${NC}"
echo -e "${BOLD}├──────────────────────┬───────────┬────────────────────────────┤${NC}"
printf  "${BOLD}│ %-20s │ %-9s │ %-26s │${NC}\n" "Example" "Transport" "URL"
echo -e "${BOLD}├──────────────────────┼───────────┼────────────────────────────┤${NC}"

for i in "${!EX_NAMES[@]}"; do
  printf "│ ${CYAN}%-20s${NC} │ %-9s │ ${GREEN}%-26s${NC} │\n" \
    "${EX_NAMES[$i]}" "${EX_TRANSPORTS[$i]}" "${EX_URLS[$i]}"
done

echo -e "${BOLD}└──────────────────────┴───────────┴────────────────────────────┘${NC}"
echo ""

# ── Inspector ────────────────────────────────────────────────────────
if [ "$OPEN_INSPECTOR" = true ]; then
  echo -e "${BOLD}Starting MCP Inspector...${NC}"
  echo -e "${DIM}Connect to any URL above using the matching transport type.${NC}"
  echo ""
  npx @modelcontextprotocol/inspector &
  PIDS+=($!)
  sleep 3
fi

echo -e "${YELLOW}Press Ctrl+C to stop all servers.${NC}"
wait
