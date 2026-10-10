#!/bin/sh
# ============================================================================
# preflight.sh — entry point of the slim mechanical gate (phase 1).
#
# All the logic lives in checks/gate.py (Python, diff-scoped, no baseline);
# this wrapper only keeps the historical command line stable:
#
#   ./preflight.sh check <repository> [base-ref] [--worktree]
#   ./preflight.sh run <repository> [base-ref]    (gate, then the LLM review)
#
# Exit codes: 0 PASSED (READY TO PUBLISH for run), 1 FAILED, 2 INCONCLUSIVE,
# 4 usage error.
# ============================================================================

set -u

TOOLKIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v python3 >/dev/null 2>&1; then
    echo "preflight ERROR: python3 not found" >&2
    exit 4
fi

if [ ! -f "$TOOLKIT_DIR/checks/gate.py" ]; then
    echo "preflight ERROR: checks/gate.py not found next to this script" >&2
    exit 4
fi

# "run": the gate, then the LLM review through a headless claude session
if [ "${1:-}" = "run" ]; then
    shift
    exec python3 "$TOOLKIT_DIR/checks/pipeline.py" "$@"
fi

exec python3 "$TOOLKIT_DIR/checks/gate.py" "$@"
