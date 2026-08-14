#!/usr/bin/env sh
set -e

if [ "${CF_MISE_BOOTSTRAPPED}" = "1" ]; then exit 0; fi

if [ "${WORKERS_CI}" = "1" ]; then
	echo "WORKERS_CI detected: ${WORKERS_CI}. Installing mise..."
	curl -fsSL https://mise.run | sh
	export PATH="${HOME}/.local/bin:${PATH}"
	export CF_MISE_BOOTSTRAPPED=1
	export MISE_CEILING_PATHS="${PWD}"

	mise trust .mise.toml
	mise install
	mise exec -- bun install --frozen-lockfile
else
	if ! command -v mise >/dev/null 2>&1; then
		echo "Error: no mise on PATH"
		exit 1
	fi

	mise trust .mise.toml
	mise install
	run -pk lefthook:install typegen
fi
