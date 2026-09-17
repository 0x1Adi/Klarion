#!/bin/sh
# Fails unless action.yml installs the scanner version being released.
#
# The GitHub Action installs the release named in inputs.version.default. If
# that default lags the tag, everyone pinning the new tag silently gets the old
# scanner. goreleaser runs this before publishing; run it before tagging too:
#
#   sh scripts/check-release-version.sh v1.2.3
set -eu

tag="${1:?usage: sh scripts/check-release-version.sh vX.Y.Z}"
action="$(dirname "$0")/../action.yml"

got="$(awk '
	/^  version:[[:space:]]*$/ { inside = 1; next }
	inside && /^  [^ #]/ { exit }
	inside && /^    default:/ {
		sub(/^    default:[[:space:]]*/, "")
		gsub(/"/, "")
		print
		exit
	}
' "$action")"

if [ "$got" != "$tag" ]; then
	echo "check-release-version: action.yml installs '${got:-nothing}', but the tag is '$tag'." >&2
	echo "Set inputs.version.default in action.yml to \"$tag\" before releasing." >&2
	exit 1
fi
echo "check-release-version: action.yml installs $tag"
