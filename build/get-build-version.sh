#!/usr/bin/env bash
git describe --tags || \
  awk -F'"' '/^var Version/{print $2}' cmd/version/version.go
