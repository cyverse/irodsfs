#!/usr/bin/env python3
"""Write many files into a mounted iRODS FUSE directory and report what breaks.

Writing a few dozen files in a row against a busy iRODS server can fail with
`Remote I/O error` (EREMOTEIO), which is how irodsfs surfaces a server-side error
such as SYS_AGENT_INIT_ERR — the server refusing to spawn another agent. The failure
depends on load and timing, so it needs a repeatable way to provoke it.

This script reports which phase failed (open, write, close, rename or read), because
they mean different things: a failing close is the data object rejecting its final
flush, while a failing open never got a connection in the first place.

    ./stress_write.py /mount/irods
    ./stress_write.py /mount/irods -n 500 -s 64K -j 8
    ./stress_write.py /mount/irods --rename --read

Whatever this prints, the reason lives in the irodsfs log; grep it for the iRODS
error code that lines up with the timestamps below.
"""

import argparse
import errno
import os
import shutil
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

PHASES = ("open", "write", "close", "rename", "read")


class Failure:
    def __init__(self, index, phase, exc):
        self.index = index
        self.phase = phase
        self.errno = getattr(exc, "errno", None)
        self.message = str(exc)

    @property
    def errno_name(self):
        if self.errno is None:
            return "-"
        return errno.errorcode.get(self.errno, f"errno {self.errno}")

    def __str__(self):
        return f"file #{self.index} failed at {self.phase}: {self.errno_name}: {self.message}"


def parse_size(text):
    units = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}
    text = text.strip().upper()

    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])

    return int(text)


def write_one(work_dir, index, payload, do_rename, do_read):
    """Run one file through its phases and return a Failure, or None on success."""
    path = os.path.join(work_dir, f"stress_{index:06d}.dat")

    try:
        handle = open(path, "wb")
    except OSError as exc:
        return Failure(index, "open", exc)

    try:
        handle.write(payload)
    except OSError as exc:
        handle.close()
        return Failure(index, "write", exc)

    # close is its own phase: this is where a staged object is flushed to iRODS,
    # and where a failure means the data may not have landed
    try:
        handle.close()
    except OSError as exc:
        return Failure(index, "close", exc)

    if do_rename:
        renamed = path + ".renamed"
        try:
            os.rename(path, renamed)
        except OSError as exc:
            return Failure(index, "rename", exc)
        path = renamed

    if do_read:
        try:
            with open(path, "rb") as reader:
                content = reader.read()
        except OSError as exc:
            return Failure(index, "read", exc)

        if content != payload:
            return Failure(index, "read", OSError(errno.EIO, f"content mismatch, got {len(content)} of {len(payload)} bytes"))

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Stress a mounted iRODS FUSE directory with many small writes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("mount_dir", help="directory inside the mount to write into")
    parser.add_argument("-n", "--count", type=int, default=200, help="number of files")
    parser.add_argument("-s", "--size", default="1K", help="file size, e.g. 512, 4K, 1M")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="parallel writers")
    parser.add_argument("--rename", action="store_true", help="rename each file after writing it")
    parser.add_argument("--read", action="store_true", help="read each file back and compare")
    parser.add_argument("--keep", action="store_true", help="keep the files instead of removing them")
    parser.add_argument("--stop-after", type=int, default=0, metavar="N", help="give up after N failures (0 = never)")
    args = parser.parse_args()

    if not os.path.isdir(args.mount_dir):
        sys.exit(f"{args.mount_dir} is not a directory")

    size = parse_size(args.size)
    payload = b"x" * size

    work_dir = os.path.join(args.mount_dir, f"stress_{os.getpid()}")
    try:
        os.makedirs(work_dir)
    except OSError as exc:
        sys.exit(f"failed to create {work_dir}: {exc}")

    print(f"writing {args.count} x {size} bytes into {work_dir} with {args.jobs} worker(s)")
    if args.rename:
        print("  each file is renamed after writing")
    if args.read:
        print("  each file is read back and compared")

    failures = []
    started = time.monotonic()

    def run(index):
        return write_one(work_dir, index, payload, args.rename, args.read)

    try:
        if args.jobs > 1:
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                for failure in pool.map(run, range(args.count)):
                    if failure is not None:
                        failures.append(failure)
        else:
            for index in range(args.count):
                failure = run(index)
                if failure is None:
                    continue

                failures.append(failure)
                if len(failures) == 1:
                    print(f"\nfirst failure after {index} successful file(s):\n  {failure}\n")
                if args.stop_after and len(failures) >= args.stop_after:
                    print(f"giving up after {len(failures)} failure(s)")
                    break
    except KeyboardInterrupt:
        print("\ninterrupted")

    elapsed = time.monotonic() - started
    attempted = args.count if not failures or args.jobs > 1 else failures[-1].index + 1
    succeeded = attempted - len(failures)

    print(f"\n{succeeded}/{attempted} files written in {elapsed:.1f}s ({succeeded / elapsed:.1f} files/s)")

    if failures:
        if args.jobs > 1:
            print(f"first failure:\n  {min(failures, key=lambda f: f.index)}")

        print("\nfailures by phase and error:")
        for (phase, name), count in sorted(Counter((f.phase, f.errno_name) for f in failures).items()):
            print(f"  {count:5d}  {phase:<6}  {name}")

        if any(f.errno == errno.EREMOTEIO for f in failures):
            print(
                "\nEREMOTEIO is irodsfs reporting an error that came from the iRODS server.\n"
                "Check the irodsfs log for the iRODS code behind it; SYS_AGENT_INIT_ERR there\n"
                "means the server would not start another agent, which is a server-side limit\n"
                "rather than anything the mount can retry around."
            )

    if not args.keep:
        try:
            shutil.rmtree(work_dir)
        except OSError as exc:
            print(f"\nfailed to remove {work_dir}: {exc}")
    else:
        print(f"\nleft {work_dir} in place")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
