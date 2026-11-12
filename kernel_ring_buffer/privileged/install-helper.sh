#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec pkexec install -o root -g root -m 0755 -- "$HERE/linspectacles-kernel-ring-buffer-helper" /usr/libexec/linspectacles-kernel-ring-buffer-helper
