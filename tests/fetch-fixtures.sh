#!/bin/sh
# Downloads the DoD InstallRoot streams the integration tests read. They are not committed: they
# are someone else's published trust material, they change without notice, and a test that pins
# bytes nobody here controls would fail for reasons unrelated to this crate. The tests skip when
# the directory is empty, so a checkout without them still passes.
set -e
dir="$(dirname "$0")/fixtures"
mkdir -p "$dir"
for s in DoD ECA JITC WCF; do
  curl -sS -o "$dir/$s.ir4" "https://crl.gds.disa.mil/pke/config/$s.ir4"
  echo "fetched $s.ir4 ($(wc -c < "$dir/$s.ir4" | tr -d ' ') bytes)"
done
