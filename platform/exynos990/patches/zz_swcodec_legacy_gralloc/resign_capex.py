#!/usr/bin/env python3
# Re-sign a compressed APEX (capex) with our own keys and, optionally, rename
# its container package.
#
# The payload data is not touched: the AVB hashtree footer is re-created with
# the same salt, so the hashtree root digest stays identical and the outer
# manifest's capexMetadata.originalApexDigest remains valid. Only the AVB key
# (apex_pubkey), the container package name and the container signatures
# change.
#
# Usage:
#   resign_capex.py --input in.apex --output out.apex --avbtool avbtool \
#       --signapk signapk --cert platform.x509.pem --key platform.pk8 \
#       --avb-key testkey_rsa4096.pem --key-name com.android.media.swcodec \
#       [--rename-package com.google.android.media.swcodec=com.android.media.swcodec]

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

ZIP_DATE = (2009, 1, 1, 0, 0, 0)
DROP = ("META-INF/", "stamp-cert-sha256")


def run(cmd):
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         universal_newlines=True)
    if res.returncode != 0:
        sys.exit("command failed: %s\n%s" % (" ".join(cmd), res.stdout))
    return res.stdout


def avb_info(avbtool, image):
    out = run([avbtool, "info_image", "--image", image])
    info = {}
    for key in ("Salt", "Root Digest", "Hash Algorithm", "Algorithm",
                "Public key (sha1)"):
        m = re.search(r"^\s*%s:\s+(\S+)" % re.escape(key), out, re.M)
        if m:
            info[key] = m.group(1)
    return info


# --- minimal protobuf reader (ApexManifest) -------------------------------
def pb_fields(buf):
    i = 0
    while i < len(buf):
        key = shift = 0
        while True:
            c = buf[i]
            i += 1
            key |= (c & 0x7F) << shift
            shift += 7
            if c < 0x80:
                break
        field, wtype = key >> 3, key & 7
        if wtype == 0:
            val = shift = 0
            while True:
                c = buf[i]
                i += 1
                val |= (c & 0x7F) << shift
                shift += 7
                if c < 0x80:
                    break
            yield field, val
        elif wtype == 2:
            ln = shift = 0
            while True:
                c = buf[i]
                i += 1
                ln |= (c & 0x7F) << shift
                shift += 7
                if c < 0x80:
                    break
            yield field, buf[i:i + ln]
            i += ln
        else:
            raise ValueError("unsupported protobuf wire type %d" % wtype)


def capex_original_digest(manifest):
    for field, val in pb_fields(manifest):
        if field == 12:  # capexMetadata
            for f2, v2 in pb_fields(val):
                if f2 == 1:  # originalApexDigest
                    return v2.decode()
    return None


# --- binary XML (AXML) string pool edit -----------------------------------
def axml_replace_string(data, old, new):
    rtype, hsize, size = struct.unpack_from("<HHI", data, 0)
    if rtype != 0x0003 or size != len(data):
        raise ValueError("not a binary XML file")
    off = hsize
    ptype, phsize, psize = struct.unpack_from("<HHI", data, off)
    if ptype != 0x0001:
        raise ValueError("string pool is not the first chunk")
    count, style_count, flags, strings_start, _ = struct.unpack_from(
        "<IIIII", data, off + 8)
    if style_count:
        raise ValueError("styled string pools are not supported")
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from("<%dI" % count, data, off + phsize)
    base = off + strings_start

    def read(idx):
        p = base + offsets[idx]
        if utf8:
            n = data[p]
            p += 1
            if n & 0x80:
                p += 1
            m = data[p]
            p += 1
            if m & 0x80:
                m = ((m & 0x7F) << 8) | data[p]
                p += 1
            return data[p:p + m].decode("utf-8")
        n = struct.unpack_from("<H", data, p)[0]
        p += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
            p += 2
        return data[p:p + 2 * n].decode("utf-16le")

    def encode(s):
        if utf8:
            raw = s.encode("utf-8")

            def ln(x):
                return bytes([x]) if x < 0x80 else bytes([(x >> 8) | 0x80, x & 0xFF])
            return ln(len(s.encode("utf-16le")) // 2) + ln(len(raw)) + raw + b"\0"
        raw = s.encode("utf-16le")
        n = len(raw) // 2
        head = struct.pack("<H", n) if n < 0x8000 else \
            struct.pack("<HH", (n >> 16) | 0x8000, n & 0xFFFF)
        return head + raw + b"\0\0"

    strings = [read(i) for i in range(count)]
    hits = [i for i, s in enumerate(strings) if s == old]
    if len(hits) != 1:
        raise ValueError("expected exactly one %r string, found %d" % (old, len(hits)))
    strings[hits[0]] = new

    blob = b""
    new_offsets = []
    for s in strings:
        new_offsets.append(len(blob))
        blob += encode(s)
    while len(blob) % 4:
        blob += b"\0"
    new_start = phsize + 4 * count
    pool = struct.pack("<HHI", 0x0001, phsize, new_start + len(blob))
    pool += struct.pack("<IIIII", count, 0, flags, new_start, 0)
    pool += data[off + 28:off + phsize]
    pool += struct.pack("<%dI" % count, *new_offsets) + blob
    out = data[:off] + pool + data[off + psize:]
    out = out[:4] + struct.pack("<I", len(out)) + out[8:]
    # Re-read to make sure the result parses and holds the new name.
    if axml_strings(out).count(new) < 1:
        raise ValueError("rewritten manifest does not contain %r" % new)
    return out


def axml_strings(data):
    _, hsize, _ = struct.unpack_from("<HHI", data, 0)
    off = hsize
    _, phsize, _ = struct.unpack_from("<HHI", data, off)
    count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", data, off + 8)
    offsets = struct.unpack_from("<%dI" % count, data, off + phsize)
    base = off + strings_start
    out = []
    for o in offsets:
        p = base + o
        if flags & 0x100:
            n = data[p]
            p += 1
            if n & 0x80:
                p += 1
            m = data[p]
            p += 1
            if m & 0x80:
                m = ((m & 0x7F) << 8) | data[p]
                p += 1
            out.append(data[p:p + m].decode("utf-8"))
        else:
            n = struct.unpack_from("<H", data, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                p += 2
            out.append(data[p:p + 2 * n].decode("utf-16le"))
    return out


def write_zip(path, entries):
    """entries: list of (name, bytes or file path, stored?)"""
    with zipfile.ZipFile(path, "w") as zf:
        for name, content, stored in entries:
            zi = zipfile.ZipInfo(name, ZIP_DATE)
            zi.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            if not isinstance(content, bytes):
                with open(content, "rb") as src:
                    content = src.read()
            zf.writestr(zi, content, compresslevel=None if stored else 9)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--avbtool", required=True)
    ap.add_argument("--signapk", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--avb-key", required=True)
    ap.add_argument("--key-name", required=True)
    ap.add_argument("--rename-package")
    args = ap.parse_args()

    old_pkg = new_pkg = None
    if args.rename_package:
        old_pkg, new_pkg = args.rename_package.split("=", 1)

    tmp = tempfile.mkdtemp(prefix="resign_capex.")
    try:
        with zipfile.ZipFile(args.input) as capex:
            names = capex.namelist()
            if "original_apex" not in names:
                sys.exit("%s is not a compressed APEX" % args.input)
            outer = {n: capex.read(n) for n in names
                     if n != "original_apex" and not n.startswith(DROP)}
            orig_path = os.path.join(tmp, "original.apex")
            with capex.open("original_apex") as src, open(orig_path, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)

        expected_digest = capex_original_digest(outer["apex_manifest.pb"])
        if not expected_digest:
            sys.exit("outer apex_manifest.pb has no originalApexDigest")

        payload = os.path.join(tmp, "apex_payload.img")
        with zipfile.ZipFile(orig_path) as inner:
            inner_names = [n for n in inner.namelist()
                           if not n.startswith(DROP) and n != "apex_pubkey"]
            inner_files = {}
            for n in inner_names:
                if n == "apex_payload.img":
                    with inner.open(n) as src, open(payload, "wb") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
                else:
                    inner_files[n] = inner.read(n)

        before = avb_info(args.avbtool, payload)
        salt = hashlib.sha256(inner_files["apex_manifest.pb"]).hexdigest()
        if before.get("Root Digest") != expected_digest:
            sys.exit("payload root digest %s does not match capex metadata %s"
                     % (before.get("Root Digest"), expected_digest))
        if before.get("Salt") != salt:
            # Keep whatever salt the image was built with; the root digest
            # depends on it.
            salt = before["Salt"]

        run([args.avbtool, "erase_footer", "--image", payload])
        run([args.avbtool, "add_hashtree_footer", "--do_not_generate_fec",
             "--algorithm", "SHA256_RSA4096", "--hash_algorithm",
             before.get("Hash Algorithm", "sha256"), "--key", args.avb_key,
             "--prop", "apex.key:%s" % args.key_name, "--salt", salt,
             "--image", payload])
        after = avb_info(args.avbtool, payload)
        if after.get("Root Digest") != expected_digest:
            sys.exit("re-signed payload root digest changed: %s" % after.get("Root Digest"))
        run([args.avbtool, "verify_image", "--image", payload, "--key", args.avb_key])

        pubkey = os.path.join(tmp, "apex_pubkey")
        run([args.avbtool, "extract_public_key", "--key", args.avb_key, "--output", pubkey])
        with open(pubkey, "rb") as f:
            pubkey_bytes = f.read()

        if old_pkg:
            inner_files["AndroidManifest.xml"] = axml_replace_string(
                inner_files["AndroidManifest.xml"], old_pkg, new_pkg)
            outer["AndroidManifest.xml"] = axml_replace_string(
                outer["AndroidManifest.xml"], old_pkg, new_pkg)

        # Inner APEX: payload and small metadata stored, the rest deflated.
        entries = [("apex_manifest.pb", inner_files.pop("apex_manifest.pb"), True),
                   ("apex_payload.img", payload, True),
                   ("apex_pubkey", pubkey_bytes, True)]
        for n in sorted(inner_files):
            entries.append((n, inner_files[n], False))
        inner_unsigned = os.path.join(tmp, "inner_unsigned.apex")
        inner_signed = os.path.join(tmp, "inner_signed.apex")
        write_zip(inner_unsigned, entries)
        run([args.signapk, "-a", "4096", "--align-file-size", args.cert, args.key,
             inner_unsigned, inner_signed])

        # Outer capex: metadata stored, original_apex deflated.
        entries = []
        for n in ("AndroidManifest.xml", "apex_build_info.pb", "apex_manifest.pb"):
            if n in outer:
                entries.append((n, outer.pop(n), True))
        outer.pop("apex_pubkey", None)
        entries.append(("apex_pubkey", pubkey_bytes, True))
        for n in sorted(outer):
            entries.append((n, outer[n], True))
        entries.append(("original_apex", inner_signed, False))
        outer_unsigned = os.path.join(tmp, "outer_unsigned.apex")
        write_zip(outer_unsigned, entries)
        run([args.signapk, "-a", "4096", "--align-file-size", args.cert, args.key,
             outer_unsigned, args.output])

        # Sanity checks on the result.
        with zipfile.ZipFile(args.output) as zf:
            if zf.read("apex_pubkey") != pubkey_bytes:
                sys.exit("output apex_pubkey mismatch")
            check = os.path.join(tmp, "check.apex")
            with zf.open("original_apex") as src, open(check, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
        with zipfile.ZipFile(check) as zf:
            zi = zf.getinfo("apex_payload.img")
            if zi.compress_type != zipfile.ZIP_STORED:
                sys.exit("apex_payload.img must be stored")
            with open(check, "rb") as f:
                f.seek(zi.header_offset)
                hdr = f.read(30)
                name_len, extra_len = struct.unpack_from("<HH", hdr, 26)
                data_off = zi.header_offset + 30 + name_len + extra_len
            if data_off % 4096:
                sys.exit("apex_payload.img is not 4 KiB aligned (offset %d)" % data_off)
            if zf.read("apex_pubkey") != pubkey_bytes:
                sys.exit("inner apex_pubkey mismatch")
            if old_pkg and new_pkg not in axml_strings(zf.read("AndroidManifest.xml")):
                sys.exit("inner manifest was not renamed")
        print("root digest %s preserved, payload offset %d, key %s"
              % (expected_digest, data_off, after.get("Public key (sha1)")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
