#!/usr/bin/env bash
# Usage: bash make_link.sh <UUID> <HOST> <WSPATH> [NAME]
set -euo pipefail
UUID="${1:?usage: make_link.sh <UUID> <HOST> <WSPATH> [NAME]}"
HOST="${2:?missing HOST (e.g. xxx.pxxlspace.cv)}"
WSPATH="${3:-/api/v1/sync}"
NAME="${4:-Pxxl-WS}"
ENC=$(WSPATH="$WSPATH" python3 -c "import urllib.parse,os; print(urllib.parse.quote(os.environ['WSPATH'], safe=''))")
echo "vless://${UUID}@${HOST}:443?encryption=none&security=tls&type=ws&host=${HOST}&path=${ENC}&sni=${HOST}#${NAME}"
