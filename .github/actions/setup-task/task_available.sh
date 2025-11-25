#!/usr/bin/env bash

if command -v task; then
	echo "TASK_AVAILABLE=true" >>"$GITHUB_ENV"
else
	echo "TASK_AVAILABLE=false" >>"$GITHUB_ENV"
fi
