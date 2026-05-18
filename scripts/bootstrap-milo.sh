#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
milo_dir="${repo_root}/vendor/milo"
milo_submodule_path="vendor/milo"

has_git_checkout() {
  [[ -d "$1/.git" || -f "$1/.git" ]]
}

has_tracked_milo_submodule() {
  [[ "$(git -C "${repo_root}" ls-files --stage -- "${milo_submodule_path}" 2>/dev/null)" == 160000* ]]
}

clone_milo() {
  if [[ -e "${milo_dir}" ]]; then
    echo "Expected ${milo_dir} to be a git checkout." >&2
    echo "Remove it or initialize this repository's vendor/milo before retrying." >&2
    exit 1
  fi

  mkdir -p "${repo_root}/vendor"
  git clone --branch feature/ecc https://github.com/kevinherron/milo.git "${milo_dir}"
}

if ! has_git_checkout "${milo_dir}"; then
  if has_git_checkout "${repo_root}" && has_tracked_milo_submodule; then
    git -C "${repo_root}" submodule update --init --recursive "${milo_submodule_path}"
  else
    clone_milo
  fi
fi

if ! has_git_checkout "${milo_dir}"; then
  echo "Unable to initialize ${milo_dir} as a git checkout." >&2
  exit 1
fi

mvn -f "${milo_dir}/pom.xml" -DskipTests install
