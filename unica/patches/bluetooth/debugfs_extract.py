#!/usr/bin/env python3
# Rootless alternative to loop-mounting an ext4 APEX payload.
#
# EXTRACT_PAYLOAD normally mounts apex_payload.img, copies the tree out and
# derives fs_config/file_context from `stat -c "%n %u %g %a"` and the
# security.selinux xattr of every entry (lost+found included). Mounting needs
# root, so without it read the same data with debugfs (e2fsprogs) instead and
# write the lists in exactly the same format.
#
# Usage: debugfs_extract.py <image> <out_dir> <fs_config> <file_context>

import os
import re
import subprocess
import sys
import tempfile

DEBUGFS = os.environ.get("DEBUGFS", "debugfs")
S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000


def run_debugfs(image, commands):
    """Run commands in one debugfs session; return {command: output}."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".cmds") as f:
        for cmd in commands:
            f.write(cmd + "\n")
        script = f.name
    try:
        res = subprocess.run([DEBUGFS, "-f", script, image], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    finally:
        os.unlink(script)
    out = res.stdout.decode("utf-8", "surrogateescape")
    results, current = {}, None
    for line in out.splitlines():
        if line.startswith("debugfs: "):
            current = line[len("debugfs: "):]
            results[current] = []
        elif current is not None:
            results[current].append(line)
    missing = [c for c in commands if c not in results]
    if missing:
        sys.exit("debugfs did not run: %s" % missing[:3])
    return results


def quote(path):
    if re.search(r'[\s"\\]', path):
        sys.exit("unsupported character in path %r" % path)
    return path


def walk(image):
    """Return [(path, mode, uid, gid)] with "/" first."""
    entries = []
    root = run_debugfs(image, ["ls -p /"])["ls -p /"]
    for line in root:
        f = line.split("/")
        if len(f) >= 7 and f[5] == ".":
            entries.append(("/", int(f[2], 8), int(f[3]), int(f[4])))
    if not entries:
        sys.exit("could not stat the root directory")
    pending = ["/"]
    while pending:
        cmds = ["ls -p %s" % quote(d) for d in pending]
        out = run_debugfs(image, cmds)
        next_dirs = []
        for d, cmd in zip(pending, cmds):
            for line in out[cmd]:
                f = line.split("/")
                # "/inode/mode/uid/gid/name/size/"
                if len(f) < 7 or f[0] != "":
                    continue
                name = f[5]
                # skip ".", ".." and unused slots (inode 0, e.g. lost+found)
                if name in ("", ".", "..") or f[1] == "0":
                    continue
                path = (d.rstrip("/") + "/" + name)
                mode = int(f[2], 8)
                entries.append((path, mode, int(f[3]), int(f[4])))
                if mode & S_IFMT == S_IFDIR:
                    next_dirs.append(path)
        pending = next_dirs
    return entries


def unescape(value):
    out = bytearray()
    i = 0
    raw = value.encode("utf-8", "surrogateescape")
    while i < len(raw):
        c = raw[i]
        if c == 0x5C and i + 1 < len(raw):  # backslash
            n = raw[i + 1]
            if 0x30 <= n <= 0x37:
                out.append(int(raw[i + 1:i + 4], 8))
                i += 4
                continue
            out.append(n)
            i += 2
            continue
        out.append(c)
        i += 1
    return bytes(out)


def contexts(image, paths):
    cmds = ["ea_get %s security.selinux" % quote(p) for p in paths]
    out = run_debugfs(image, cmds)
    result = {}
    for p, cmd in zip(paths, cmds):
        ctx = ""
        for line in out[cmd]:
            m = re.match(r'^security\.selinux \(\d+\) = "(.*)"$', line)
            if m:
                # getfattr --only-values inside $(...) loses the trailing NUL
                ctx = unescape(m.group(1)).replace(b"\0", b"").decode()
        result[p] = ctx
    return result


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__ if __doc__ else "bad usage")
    image, out_dir, fs_config, file_context = sys.argv[1:]
    entries = walk(image)
    ctx = contexts(image, [e[0] for e in entries])

    os.makedirs(out_dir, exist_ok=True)
    dumps, links, dirs = [], [], []
    for path, mode, _, _ in entries:
        if path == "/" or path == "/lost+found" or path.startswith("/lost+found/"):
            continue
        dest = os.path.join(out_dir, path.lstrip("/"))
        kind = mode & S_IFMT
        if kind == S_IFDIR:
            os.makedirs(dest, exist_ok=True)
            dirs.append((dest, mode))
        elif kind == S_IFREG:
            dumps.append("dump %s %s" % (quote(path), quote(dest)))
            dirs.append((dest, mode))
        elif kind == S_IFLNK:
            links.append((path, dest))
        else:
            sys.exit("unsupported file type %o for %s" % (kind, path))
    if dumps:
        run_debugfs(image, dumps)
    if links:
        cmds = ["stat %s" % quote(p) for p, _ in links]
        out = run_debugfs(image, cmds)
        for (path, dest), cmd in zip(links, cmds):
            target = None
            for line in out[cmd]:
                m = re.match(r'^Fast link dest: "(.*)"$', line)
                if m:
                    target = unescape(m.group(1)).decode()
            if target is None:
                with tempfile.NamedTemporaryFile(delete=False) as t:
                    tmp = t.name
                run_debugfs(image, ["dump %s %s" % (quote(path), quote(tmp))])
                with open(tmp, "rb") as t:
                    target = t.read().decode()
                os.unlink(tmp)
            os.symlink(target, dest)
    for dest, mode in dirs:
        if not os.path.exists(dest):
            sys.exit("debugfs failed to extract %s" % dest)
        os.chmod(dest, mode & 0o7777)

    # Same lines as the mount-based path after its sed clean-up.
    with open(fs_config, "w") as f:
        for path, mode, uid, gid in sorted(entries):
            rel = "" if path == "/" else path.lstrip("/")
            f.write("%s %d %d %o capabilities=0x0\n" % (rel, uid, gid, mode & 0o7777))
    with open(file_context, "w") as f:
        for path, _, _, _ in sorted(entries):
            line = "%s %s" % (path, ctx[path])
            for ch in ".+[]*":
                line = line.replace(ch, "\\" + ch)
            f.write(line + "\n")


if __name__ == "__main__":
    main()
