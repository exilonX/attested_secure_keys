#!/usr/bin/env bash
# Publish packages/<name> to pub.dev, unless that exact version is already there.
#
# `dart pub publish` treats an already-published version as a hard ERROR, not a
# no-op. Because the release job publishes the four federated packages as
# sequential `bash -e` steps, one such error aborts the rest of the release —
# which is how the v0.1.1 tag failed with nothing published at all.
#
# Two cases hit this in normal operation:
#   1. A re-run after a partial release (some packages uploaded, a later one
#      failed) — the re-run dies on the first, already-uploaded package.
#   2. A release where a package's version did not change.
# In both, "already published" is the desired end state, so skip and continue.
set -euo pipefail

pkg="${1:?usage: publish-if-new.sh <package-directory-name>}"
ver=$(awk '/^version:/ {print $2; exit}' "packages/$pkg/pubspec.yaml")

# pub.dev answers 404 for an unknown version; -f turns that into a non-zero exit.
if curl -sfo /dev/null "https://pub.dev/api/packages/$pkg/versions/$ver"; then
  echo "::notice::$pkg $ver is already on pub.dev — skipping."
  exit 0
fi

echo "Publishing $pkg $ver to pub.dev…"
cd "packages/$pkg"
dart pub publish --force
