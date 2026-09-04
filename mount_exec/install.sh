#!/usr/bin/env bash
# Install irodsfs and its mount(8) helper. This works from a source checkout
# or from a release archive whose assets are placed next to this script.
set -euo pipefail

binary_name="irodsfs"
helper_name="mount.irodsfs"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -x "${script_dir}/${binary_name}" ]]; then
    binary_path="${script_dir}/${binary_name}"
    helper_path="${script_dir}/${helper_name}"
else
    source_root="$(cd -- "${script_dir}/.." && pwd)"
    binary_path="${source_root}/bin/${binary_name}"
    helper_path="${script_dir}/${helper_name}"
fi

if [[ $# -ne 0 ]]; then
    echo "usage: sudo $0" >&2
    exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
    echo "run this script as root (for example, sudo $0)" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required by ${helper_name}" >&2
    exit 1
fi
if [[ ! -c /dev/fuse ]]; then
    echo "/dev/fuse is unavailable; install and enable FUSE before installing ${binary_name}" >&2
    exit 1
fi
if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v fusermount >/dev/null 2>&1; then
    echo "fusermount3 or fusermount is required; install a FUSE userspace package first" >&2
    exit 1
fi
if [[ ! -x ${binary_path} ]]; then
    echo "service binary is missing or not executable: ${binary_path}" >&2
    exit 1
fi
if [[ ! -f ${helper_path} ]]; then
    echo "mount helper is missing: ${helper_path}" >&2
    exit 1
fi

# /usr/bin is in mount helpers' default PATH, and /sbin is searched by
# mount(8) for mount.<type> helper programs.
install -d -o root -g root -m 0755 /usr/bin /sbin
install -o root -g root -m 0755 "${binary_path}" "/usr/bin/${binary_name}"
install -o root -g root -m 0755 "${helper_path}" "/sbin/${helper_name}"

echo "installed /usr/bin/${binary_name} and /sbin/${helper_name}"
