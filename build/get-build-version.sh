#!/usr/bin/env bash

awk -F'"' '/^var Version/{print $2}' cmd/version/version.go
