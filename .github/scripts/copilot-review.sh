#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  pr|snapshot) mode="$1" ;;
  *) echo "Usage: bash copilot-review.sh {pr|snapshot}" >&2; exit 2 ;;
esac

# Never run the CLI in the checkout or load its instructions/configuration.
cd -- "${RUNNER_TEMP:?RUNNER_TEMP must name an existing scratch directory}"
export COPILOT_HOME="$RUNNER_TEMP/copilot-home"
command=(copilot --model "${COPILOT_MODEL:-claude-haiku-5.5}" --context long_context
  --silent --output-format json
  --available-tools=none --disable-builtin-mcps --no-custom-instructions
  --no-auto-update --max-ai-credits 30)

if [[ "$mode" == snapshot ]]; then
  # Leave time for the always-run summary inside the ten-minute job limit.
  timeout 5m "${command[@]}" < prompt.txt > events.jsonl 2> copilot.stderr
elif ! "${command[@]}" < prompt.txt > events.jsonl; then
  echo "Copilot CLI failed; no compliance verdict was accepted." | tee -a "$GITHUB_STEP_SUMMARY"
  jq -r 'select(.type == "session.error") | .data.message' events.jsonl \
    | tee -a "$GITHUB_STEP_SUMMARY"
  exit 1
fi
