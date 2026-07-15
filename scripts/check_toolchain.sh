#!/usr/bin/env sh
set -eu

required_rust='rustc 1.88.0 '
actual_rust="$(rustc --version)"

case "$actual_rust" in
  "$required_rust"*) ;;
  *)
    printf '%s\n' "expected rustc 1.88.0, received: $actual_rust" >&2
    exit 1
    ;;
esac

command -v cargo >/dev/null
command -v cmake >/dev/null
command -v ninja >/dev/null
command -v cc >/dev/null

printf '%s\n' "$actual_rust"
cargo --version
cmake --version | sed -n '1p'
ninja --version
cc --version | sed -n '1p'
