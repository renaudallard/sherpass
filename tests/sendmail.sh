#!/bin/sh
#
# Stand-in for sendmail(8) used by the tests. Each message is stored as
# a numbered file in the directory given as first argument, the other
# arguments are ignored.

set -eu

mkdir -p "$1"
n=$(ls "$1" | wc -l)
cat > "$1/$((n + 1))"
