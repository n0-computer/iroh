#!/bin/sh
# Validate all SVG diagrams in docs/internals/diagrams/
# Requires: xmllint (ships with macOS, available via libxml2 on Linux)
# Usage: ./docs/internals/validate.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIAGRAMS_DIR="$SCRIPT_DIR/diagrams"
ERRORS=0

if ! command -v xmllint >/dev/null 2>&1; then
    echo "ERROR: xmllint not found. Install libxml2." >&2
    exit 1
fi

if [ ! -d "$DIAGRAMS_DIR" ]; then
    echo "ERROR: diagrams directory not found at $DIAGRAMS_DIR" >&2
    exit 1
fi

SVG_COUNT=0
for svg in "$DIAGRAMS_DIR"/*.svg; do
    [ -f "$svg" ] || continue
    SVG_COUNT=$((SVG_COUNT + 1))
    if xmllint --noout "$svg" 2>/dev/null; then
        echo "  OK  $(basename "$svg")"
    else
        echo " FAIL $(basename "$svg")"
        xmllint --noout "$svg" 2>&1 | sed 's/^/       /'
        ERRORS=$((ERRORS + 1))
    fi
done

if [ "$SVG_COUNT" -eq 0 ]; then
    echo "WARNING: No SVG files found in $DIAGRAMS_DIR"
    exit 1
fi

echo ""
echo "$SVG_COUNT SVGs checked, $ERRORS errors."

if [ "$ERRORS" -gt 0 ]; then
    exit 1
fi
