#!/bin/sh
# Klarion installer — downloads a released binary, verifies its checksum, and
# installs it to a bin directory. POSIX sh, dependency-light (curl or wget).
#
#   curl -fsSL https://raw.githubusercontent.com/0x1Adi/Klarion/main/scripts/install.sh | sh
#
# Environment overrides:
#   KLARION_VERSION   release tag to install (default: latest)
#   KLARION_INSTALL   install directory (default: /usr/local/bin)
#   KLARION_REPO      owner/repo (default: 0x1Adi/Klarion)
set -eu

REPO="${KLARION_REPO:-0x1Adi/Klarion}"
INSTALL_DIR="${KLARION_INSTALL:-/usr/local/bin}"
VERSION="${KLARION_VERSION:-latest}"
BINARY="klarion"

err() {
	echo "install.sh: error: $*" >&2
	exit 1
}

info() {
	echo "install.sh: $*" >&2
}

have() {
	command -v "$1" >/dev/null 2>&1
}

# --- pick a downloader --------------------------------------------------------
if have curl; then
	dl() { curl -fsSL "$1" -o "$2"; }
	dl_stdout() { curl -fsSL "$1"; }
elif have wget; then
	dl() { wget -q "$1" -O "$2"; }
	dl_stdout() { wget -qO- "$1"; }
else
	err "need curl or wget installed"
fi

# --- detect OS ----------------------------------------------------------------
os="$(uname -s)"
case "$os" in
Linux) os="linux" ;;
Darwin) os="darwin" ;;
MINGW* | MSYS* | CYGWIN*) os="windows" ;;
*) err "unsupported OS: $os" ;;
esac

# --- detect arch (match goreleaser naming) ------------------------------------
arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
arm64 | aarch64) arch="arm64" ;;
*) err "unsupported architecture: $arch" ;;
esac

# --- resolve version ----------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
	info "resolving latest release for $REPO"
	# Parse the tag_name from the GitHub API without requiring jq.
	VERSION="$(dl_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
		| grep '"tag_name"' | head -n1 | cut -d'"' -f4)"
	[ -n "$VERSION" ] || err "could not determine latest version"
fi
# Version without a leading 'v' — goreleaser archive names drop it.
ver_noprefix="${VERSION#v}"

# --- archive naming (must match .goreleaser.yaml) -----------------------------
ext="tar.gz"
[ "$os" = "windows" ] && ext="zip"
archive="${BINARY}_${ver_noprefix}_${os}_${arch}.${ext}"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "downloading ${archive}"
dl "${base_url}/${archive}" "${tmp}/${archive}" \
	|| err "download failed for ${base_url}/${archive}"

info "downloading checksums"
dl "${base_url}/checksums.txt" "${tmp}/checksums.txt" \
	|| err "checksum download failed"

# --- verify checksum ----------------------------------------------------------
if have sha256sum; then
	sha="$(sha256sum "${tmp}/${archive}" | awk '{print $1}')"
elif have shasum; then
	sha="$(shasum -a 256 "${tmp}/${archive}" | awk '{print $1}')"
else
	err "need sha256sum or shasum to verify the download"
fi

expected="$(grep " ${archive}\$" "${tmp}/checksums.txt" | awk '{print $1}')"
[ -n "$expected" ] || err "no checksum entry for ${archive}"
[ "$sha" = "$expected" ] || err "checksum mismatch (got ${sha}, want ${expected})"
info "checksum verified"

# --- verify signature (optional) ----------------------------------------------
# The checksum above proves the archive downloaded intact. It does not prove who
# produced it: anyone able to replace the archive could replace checksums.txt
# next to it. Releases are cosign-signed keylessly, so when cosign is available
# we verify that checksums.txt was signed by this repository's release workflow.
#
# Absent cosign we continue with checksum-only verification rather than refusing
# to install — but we say so, because the guarantee is weaker.
if have cosign; then
	if dl "${base_url}/checksums.txt.sig" "${tmp}/checksums.txt.sig" \
		&& dl "${base_url}/checksums.txt.pem" "${tmp}/checksums.txt.pem"; then
		if cosign verify-blob "${tmp}/checksums.txt" \
			--signature "${tmp}/checksums.txt.sig" \
			--certificate "${tmp}/checksums.txt.pem" \
			--certificate-identity-regexp "^https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/" \
			--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
			>/dev/null 2>&1; then
			info "signature verified (cosign)"
		else
			err "signature verification FAILED for checksums.txt — refusing to install"
		fi
	else
		info "no signature published for ${VERSION}; continuing with checksum-only verification"
	fi
else
	info "cosign not found; continuing with checksum-only verification"
	info "  install cosign to additionally verify the release signature"
fi

# --- extract ------------------------------------------------------------------
if [ "$ext" = "zip" ]; then
	have unzip || err "need unzip to extract ${archive}"
	unzip -q "${tmp}/${archive}" -d "${tmp}"
else
	tar -xzf "${tmp}/${archive}" -C "${tmp}"
fi

bin_name="$BINARY"
[ "$os" = "windows" ] && bin_name="${BINARY}.exe"
[ -f "${tmp}/${bin_name}" ] || err "binary ${bin_name} not found in archive"
chmod +x "${tmp}/${bin_name}"

# --- install ------------------------------------------------------------------
dest="${INSTALL_DIR}/${bin_name}"
if [ -w "$INSTALL_DIR" ] 2>/dev/null; then
	mv "${tmp}/${bin_name}" "$dest"
else
	info "elevating with sudo to write ${INSTALL_DIR}"
	have sudo || err "cannot write ${INSTALL_DIR} and sudo is unavailable"
	sudo mv "${tmp}/${bin_name}" "$dest"
fi

info "installed ${BINARY} ${VERSION} to ${dest}"
"$dest" version 2>/dev/null || true
