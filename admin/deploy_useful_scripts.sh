#!/usr/bin/env bash
set -euo pipefail

# Resolve REPO_DIR as the parent of the directory containing this script
# admin/deploy_useful_scripts.sh  -> REPO_DIR is the repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LIVE_DIR="/apps/common/useful_scripts"

# Listing only these files 
files=(
  getjobutilurl
  getusage
  gpumon
  gpumon-q
  interact
  jobload
  lmstat
  loginusage
  nodestat
  quota
  setup_app
  showjobprocessesusage
  showjobusage
  shownodeusage
  showqos
  showusage
)



echo "Deploying useful_scripts from: $REPO_DIR to $LIVE_DIR"
echo

for f in "${files[@]}"; do
  src="$REPO_DIR/$f"
  dst="$LIVE_DIR/$f"

  if [[ ! -f "$src" ]]; then
    echo "WARNING: $src does not exist in repo, skipping"
    continue
  fi

  if [[ -f "$dst" ]]; then
    # Check if file contents differ
    if cmp -s "$src" "$dst"; then
      echo "No change for $f, skipping"
      continue
    fi

    echo "Updating existing script: $f"
    # Overwrite contents only. Owner, group, mode are preserved.
    cp "$src" "$dst"
  else
    echo "Installing new script: $f"
    cp "$src" "$dst"
    chmod 755 "$dst"
  fi
done

echo
echo "Deployment finished."
