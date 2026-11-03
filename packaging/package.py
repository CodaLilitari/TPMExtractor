#!/usr/bin/env python3
# TPMExtractor fork - builds the release packages (Python 3.8+, standard library only).
# Copyright 2026 the TPMExtractor fork contributors. Licensed under the Apache License,
# Version 2.0 (see LICENSE). New file in the fork (see CHANGES.md).
"""Packages a built tpmextractor for a release, the same way on every system.

  package.py win64 PROGRAM OUTDIR             OUTDIR/TPMExtractor-fork-win64.zip
  package.py linux-x64 PROGRAM OUTDIR         OUTDIR/TPMExtractor-fork-linux-x64.tar.gz
  package.py macos-universal PROGRAM OUTDIR   OUTDIR/TPMExtractor-fork-macos-universal.zip
  package.py sums OUTDIR                      OUTDIR/SHA256SUMS.txt for the three packages

PROGRAM is the built executable. It is checked before it is packaged: a 64-bit x86 Windows
program (PE), a 64-bit x86 Linux program (ELF), or a universal macOS program (Mach-O) holding
both arm64 and x86_64. Each package holds the program (tpmextractor.exe or tpmextractor) with
README.md, LICENSE, NOTICE and CHANGES.md from the repository, and MACOS.txt (this folder) for
macOS. The zip files are flat; the tar.gz holds a folder named after it. Entries come in a fixed
order with fixed permissions (programs 755, text 644), owner 0 and the time SOURCE_DATE_EPOCH
(default: now), so the same inputs give the same bytes. No game data goes into a package.
"""

import argparse
import gzip
import hashlib
import io
import os
import stat
import struct
import sys
import tarfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCS = ('README.md', 'LICENSE', 'NOTICE', 'CHANGES.md')

# platform: (package file, program name inside, extra files from this folder)
PACKAGES = {
    'win64': ('TPMExtractor-fork-win64.zip', 'tpmextractor.exe', ()),
    'linux-x64': ('TPMExtractor-fork-linux-x64.tar.gz', 'tpmextractor', ()),
    'macos-universal': ('TPMExtractor-fork-macos-universal.zip', 'tpmextractor', ('MACOS.txt',)),
}

ZIP_EPOCH_MIN = 315532800       # 1980-01-01, the earliest time a zip entry can hold
PE_AMD64 = 0x8664
ELF_X86_64 = 0x3E
MACHO_X86_64 = 0x01000007
MACHO_ARM64 = 0x0100000C


class PackageError(Exception):
    pass


def u16le(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32le(b, o):
    return struct.unpack_from('<I', b, o)[0]


def check_program(platform, data):
    """Raises PackageError unless `data` is the kind of program the platform's package holds."""
    try:
        if platform == 'win64':
            if data[:2] != b'MZ':
                raise PackageError('not a Windows program (no MZ header)')
            pe = u32le(data, 0x3C)
            if data[pe:pe + 4] != b'PE\0\0':
                raise PackageError('not a Windows program (no PE header)')
            if u16le(data, pe + 4) != PE_AMD64:
                raise PackageError('a Windows program for machine 0x%04X, not x86-64' % u16le(data, pe + 4))
        elif platform == 'linux-x64':
            if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
                raise PackageError('not a 64-bit little-endian ELF program')
            if u16le(data, 18) != ELF_X86_64:
                raise PackageError('an ELF program for machine 0x%X, not x86-64' % u16le(data, 18))
        elif platform == 'macos-universal':
            magic = struct.unpack_from('>I', data, 0)[0]
            if magic not in (0xCAFEBABE, 0xCAFEBABF):
                raise PackageError('not a universal (fat) Mach-O program')
            count = struct.unpack_from('>I', data, 4)[0]
            size = 20 if magic == 0xCAFEBABE else 32
            if not 0 < count <= 16:
                raise PackageError('a universal program with %d architectures' % count)
            cpus = {struct.unpack_from('>I', data, 8 + i * size)[0] for i in range(count)}
            missing = [n for n, c in (('arm64', MACHO_ARM64), ('x86_64', MACHO_X86_64)) if c not in cpus]
            if missing:
                raise PackageError('the universal program lacks %s' % ' and '.join(missing))
        else:
            raise PackageError('unknown platform %r' % platform)
    except struct.error:
        raise PackageError('too short for a program')


def read(path):
    with open(path, 'rb') as f:
        return f.read()


def entries_for(platform, program_path):
    """[(name in the package, bytes, permissions)] in package order."""
    _, program_name, extra = PACKAGES[platform]
    program = read(program_path)
    check_program(platform, program)
    out = [(program_name, program, 0o755)]
    out += [(n, read(os.path.join(ROOT, n)), 0o644) for n in DOCS]
    out += [(n, read(os.path.join(HERE, n)), 0o644) for n in extra]
    return out


def write_atomic(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.replace(tmp, path)


def zip_bytes(entries, epoch):
    buf = io.BytesIO()
    when = time.gmtime(max(epoch, ZIP_EPOCH_MIN))[:6]
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=when)
            info.create_system = 3                    # Unix permissions, kept by unzip and Finder
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data, compresslevel=9)
    return buf.getvalue()


def tar_gz_bytes(folder, entries, epoch):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as t:
        def info(name, kind, mode, size=0):
            ti = tarfile.TarInfo(name)
            ti.type, ti.mode, ti.size, ti.mtime = kind, mode, size, epoch
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ''
            return ti
        t.addfile(info(folder, tarfile.DIRTYPE, 0o755))
        for name, data, mode in entries:
            t.addfile(info(folder + '/' + name, tarfile.REGTYPE, mode, len(data)), io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=out, compresslevel=9, mtime=epoch) as g:
        g.write(raw.getvalue())
    return out.getvalue()


def build(platform, program_path, out_dir, epoch):
    package, _, _ = PACKAGES[platform]
    entries = entries_for(platform, program_path)
    if package.endswith('.zip'):
        data = zip_bytes(entries, epoch)
    else:
        data = tar_gz_bytes(package[:-len('.tar.gz')], entries, epoch)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, package)
    write_atomic(path, data)
    print('%s: %d bytes, sha256 %s (%s)' % (package, len(data), hashlib.sha256(data).hexdigest(),
                                            ', '.join(e[0] for e in entries)))
    return path


def sums(out_dir):
    lines = []
    for package, _, _ in PACKAGES.values():
        path = os.path.join(out_dir, package)
        if not os.path.isfile(path):
            raise PackageError('%s is missing; build all three packages first' % path)
        lines.append('%s  %s\n' % (hashlib.sha256(read(path)).hexdigest(), package))
    write_atomic(os.path.join(out_dir, 'SHA256SUMS.txt'), ''.join(lines).encode('ascii'))
    sys.stdout.write(''.join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('platform', choices=sorted(PACKAGES) + ['sums'])
    ap.add_argument('paths', nargs='+', metavar='PATH', help='PROGRAM OUTDIR, or OUTDIR for sums')
    args = ap.parse_args(argv)
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH') or time.time())
    try:
        if args.platform == 'sums':
            if len(args.paths) != 1:
                ap.error('sums takes one argument: OUTDIR')
            sums(args.paths[0])
        else:
            if len(args.paths) != 2:
                ap.error('%s takes two arguments: PROGRAM OUTDIR' % args.platform)
            build(args.platform, args.paths[0], args.paths[1], epoch)
    except (PackageError, OSError) as e:
        print('package.py: error: %s' % e, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
