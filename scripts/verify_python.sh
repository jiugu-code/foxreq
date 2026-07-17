#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"

python=${PYTHON:-python3}
for command in "$python" cargo rustc cmake ninja git; do
  if ! command -v "$command" >/dev/null 2>/dev/null; then
    echo "required tool is missing: $command" >&2
    exit 2
  fi
done

if ! "$python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 2)'; then
  echo "Python 3.10+ is required" >&2
  exit 2
fi

available_kib=$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)
case "$available_kib" in
  ''|*[!0-9]*)
    echo "could not read MemAvailable" >&2
    exit 2
    ;;
esac
available_mib=$((available_kib / 1024))
echo "available_memory_mib=$available_mib"
if [ "$available_mib" -lt 4096 ]; then
  echo "available physical memory is below the 4096 MiB verification gate" >&2
  exit 2
fi

: "${FOXREQ_RUNTIME_FIREFOX_140_ESR:?set FOXREQ_RUNTIME_FIREFOX_140_ESR}"
: "${FOXREQ_NSS_RUNTIME_DIR:?set FOXREQ_NSS_RUNTIME_DIR for Firefox 152}"
: "${FOXREQ_PY_TEST_FIXTURE:?set FOXREQ_PY_TEST_FIXTURE}"
: "${FOXREQ_LINUX_WHEEL:?set FOXREQ_LINUX_WHEEL}"

for directory in \
  "$FOXREQ_RUNTIME_FIREFOX_140_ESR" \
  "$FOXREQ_NSS_RUNTIME_DIR" \
  "$FOXREQ_PY_TEST_FIXTURE"; do
  if [ ! -d "$directory" ]; then
    echo "required verification directory is missing" >&2
    exit 2
  fi
done
if [ ! -f "$FOXREQ_LINUX_WHEEL" ]; then
  echo "Linux wheel is missing" >&2
  exit 2
fi

export CARGO_BUILD_JOBS=1
export CMAKE_BUILD_PARALLEL_LEVEL=1
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p foxreq-core --no-default-features
cargo test -p foxreq-py --lib

cmake -S native/nss-shim -B build/nss-shim-linux-stub -G Ninja \
  -DFOXREQ_NSS_STUB=ON -DFOXREQ_NSS_REAL=OFF -DBUILD_TESTING=ON
cmake --build build/nss-shim-linux-stub --parallel 1
ctest --test-dir build/nss-shim-linux-stub --output-on-failure

cmake -S native/nss-shim -B build/nss-shim-linux-real -G Ninja \
  -DFOXREQ_NSS_STUB=OFF -DFOXREQ_NSS_REAL=ON -DBUILD_TESTING=ON
cmake --build build/nss-shim-linux-real --parallel 1
ctest --test-dir build/nss-shim-linux-real --output-on-failure

"$python" -m scripts.runtime.test_real_tls \
  --runtime "$FOXREQ_NSS_RUNTIME_DIR" \
  --python-api "$python"
"$python" -W error::ResourceWarning -m unittest \
  tests.python.test_real_http -v
"$python" -W error::ResourceWarning -m unittest \
  tests.python.test_real_api -v
"$python" -W error::ResourceWarning -m unittest discover \
  -s tests/python -t . -v
"$python" -m pip check
git diff --check

if pgrep -f 'foxreq[.]_profile_worker' >/dev/null 2>/dev/null; then
  echo "foxreq profile worker remained after verification" >&2
  exit 1
fi
