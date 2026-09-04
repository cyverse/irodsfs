#!/usr/bin/env bash
# Download and install the latest irodsfs Linux release.
set -euo pipefail

repository="cyverse/irodsfs"
binary_name="irodsfs"

for command in curl tar uname mktemp grep; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "${command} is required to install ${binary_name}" >&2
        exit 1
    fi
done

if [[ $(uname -s) != Linux ]]; then
    echo "${binary_name} is supported only on Linux" >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64) release_arch="amd64" ;;
    i386|i486|i586|i686) release_arch="386" ;;
    aarch64|arm64) release_arch="arm64" ;;
    arm|armv6l|armv7l) release_arch="arm" ;;
    *)
        echo "unsupported Linux architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

release_json="$(curl -fsSL "https://api.github.com/repos/${repository}/releases/latest")" || {
    echo "failed to find the latest ${binary_name} GitHub release" >&2
    exit 1
}
asset_suffix="-linux-${release_arch}.tar.gz"
asset_url="$(printf '%s' "${release_json}" |
    grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' |
    cut -d '"' -f 4 |
    grep -F -- "${asset_suffix}" |
    head -n 1 || true)"
if [[ -z ${asset_url} ]]; then
    echo "the latest release has no ${release_arch} Linux archive" >&2
    exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/${binary_name}.XXXXXX")"
trap 'rm -rf "${work_dir}"' EXIT
echo "downloading ${asset_url}"
curl -fsSL "${asset_url}" -o "${work_dir}/release.tar.gz"
tar -xzf "${work_dir}/release.tar.gz" -C "${work_dir}"

for required_file in "${binary_name}" mount.irodsfs install.sh; do
    if [[ ! -f "${work_dir}/${required_file}" ]]; then
        echo "release archive is missing ${required_file}" >&2
        exit 1
    fi
done
if [[ ! -x "${work_dir}/${binary_name}" || ! -x "${work_dir}/install.sh" ]]; then
    echo "release archive contains a non-executable installer or binary" >&2
    exit 1
fi

if [[ ${EUID} -eq 0 ]]; then
    "${work_dir}/install.sh"
elif ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required when the installer is not run as root" >&2
    exit 1
else
    sudo "${work_dir}/install.sh"
fi
