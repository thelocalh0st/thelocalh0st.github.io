#!/usr/bin/env python3
"""upgrade_hive.py - Windows feature-update evidence from offline registry hives.

Reads a SYSTEM hive (and optionally SOFTWARE) straight from disk, no Windows APIs:

  upgrade_history.csv   every in-place upgrade: old build, its install date, when the
                        upgrade began (Source OS key name), next build and install date
  device_migration.csv  the DeviceMigration PnP snapshot Setup takes of the old OS,
                        one row per device instance: BusDeviceDesc, LastPresentDate (when
                        a disconnected device was last seen), OnlyInSnapshot = not in Enum
  upgrade_apps.csv      Setup\\Upgrade\\Appx: the old OS's app inventory

DeviceMigration lives in two places and is not parsed by RECmd's stock batch files,
RegRipper, Plaso or Velociraptor's built-ins (as of October 2026):
  ControlSet00N\\Control\\DeviceMigration
  Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration

usage: python3 upgrade_hive.py SYSTEM [--software SOFTWARE] [-o outdir]

Dirty hives: replay the .LOG1/.LOG2 transaction logs first (e.g. rla.exe), the script
warns when the header says the hive was not cleanly written.

Feature Update Evidence Kit by Sujay Adkesar - https://thelocalh0st.com   License: MIT
Stdlib only, Python 3.8+.
"""
import argparse
import csv
import datetime as dt
import os
import re
import struct
import sys

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11
VENDORS = {
    '03F0': 'HP', '0408': 'Quanta', '045E': 'Microsoft', '046D': 'Logitech', '04E8': 'Samsung', '04F2': 'Chicony', '054C': 'Sony',
    '058F': 'Alcor Micro', '05AC': 'Apple', '0781': 'SanDisk', '0930': 'Toshiba', '0951': 'Kingston', '0BC2': 'Seagate',
    '0BDA': 'Realtek', '1058': 'Western Digital', '090C': 'Silicon Motion', '13D3': 'IMC Networks', '13FE': 'Phison',
    '152D': 'JMicron', '174C': 'ASMedia', '18A5': 'Verbatim', '18D1': 'Google', '1949': 'Amazon', '22B8': 'Motorola',
    '22D9': 'OPPO / realme', '2717': 'Xiaomi', '2A70': 'OnePlus', '30C9': 'Luxvisions', '413C': 'Dell', '8087': 'Intel',
}


def filetime(v):
    if not v or v < 116444736000000000:
        return ''
    return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v // 10)).strftime('%Y-%m-%d %H:%M:%SZ')


class Hive:
    """Minimal regf reader: keys, values, lf/lh/li/ri lists, big data (db)."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.b = f.read()
        if self.b[:4] != b'regf':
            raise ValueError('%s is not a registry hive (no regf signature)' % path)
        seq1, seq2 = struct.unpack_from('<II', self.b, 4)
        self.dirty = seq1 != seq2
        self.written = filetime(struct.unpack_from('<Q', self.b, 12)[0])
        self.root = self.key_at(struct.unpack_from('<I', self.b, 36)[0])

    def cell(self, off):
        return 4096 + off + 4

    def key_at(self, off):
        p = self.cell(off)
        if self.b[p:p + 2] != b'nk':
            raise ValueError('bad nk at %#x' % off)
        return Key(self, p)


class Key:
    def __init__(self, hive, p):
        self.h, self.p = hive, p
        b = hive.b
        flags = struct.unpack_from('<H', b, p + 2)[0]
        self.last_write = filetime(struct.unpack_from('<Q', b, p + 4)[0])
        self.n_sub, = struct.unpack_from('<I', b, p + 20)
        self.sub_list, = struct.unpack_from('<I', b, p + 28)
        self.n_val, = struct.unpack_from('<I', b, p + 36)
        self.val_list, = struct.unpack_from('<I', b, p + 40)
        nlen, = struct.unpack_from('<H', b, p + 72)
        raw = b[p + 76:p + 76 + nlen]
        self.name = raw.decode('latin-1') if flags & 0x20 else raw.decode('utf-16-le', 'replace')

    def subkeys(self):
        if not self.n_sub or self.sub_list == 0xFFFFFFFF:
            return []
        out = []
        self._walk_list(self.sub_list, out)
        return [self.h.key_at(o) for o in out]

    def _walk_list(self, off, out):
        b, p = self.h.b, self.h.cell(off)
        sig, n = b[p:p + 2], struct.unpack_from('<H', b, p + 2)[0]
        if sig in (b'lf', b'lh'):
            out.extend(struct.unpack_from('<I', b, p + 4 + 8 * i)[0] for i in range(n))
        elif sig == b'li':
            out.extend(struct.unpack_from('<I', b, p + 4 + 4 * i)[0] for i in range(n))
        elif sig == b'ri':
            for i in range(n):
                self._walk_list(struct.unpack_from('<I', b, p + 4 + 4 * i)[0], out)

    def subkey(self, name):
        name = name.lower()
        for k in self.subkeys():
            if k.name.lower() == name:
                return k
        return None

    def path(self, path):
        k = self
        for part in [x for x in re.split(r'[\\/]', path) if x]:
            k = k.subkey(part) if k else None
        return k

    def values(self):
        if not self.n_val or self.val_list == 0xFFFFFFFF:
            return {}
        b, out = self.h.b, {}
        lp = self.h.cell(self.val_list)
        for i in range(self.n_val):
            vp = self.h.cell(struct.unpack_from('<I', b, lp + 4 * i)[0])
            if b[vp:vp + 2] != b'vk':
                continue
            nlen, size, doff, typ, flags = struct.unpack_from('<HIIIH', b, vp + 2)
            raw = b[vp + 20:vp + 20 + nlen]
            name = (raw.decode('latin-1') if flags & 1 else raw.decode('utf-16-le', 'replace')) if nlen else '(default)'
            out[name] = decode(typ, self._data(size, doff, vp))
        return out

    def _data(self, size, doff, vp):
        b = self.h.b
        if size & 0x80000000:
            return b[vp + 8:vp + 8 + (size & 0x7FFFFFFF)]
        p = self.h.cell(doff)
        if size > 16344 and b[p:p + 2] == b'db':
            n, lst = struct.unpack_from('<HI', b, p + 2)
            lp, chunks = self.h.cell(lst), []
            for i in range(n):
                sp = self.h.cell(struct.unpack_from('<I', b, lp + 4 * i)[0])
                chunks.append(b[sp:sp + 16344])
            return b''.join(chunks)[:size]
        return b[p:p + size]


def decode(typ, d):
    if typ in (REG_SZ, REG_EXPAND_SZ):
        return d.decode('utf-16-le', 'replace').split('\x00')[0]
    if typ == REG_MULTI_SZ:
        return [s for s in d.decode('utf-16-le', 'replace').split('\x00') if s]
    if typ == REG_DWORD and len(d) >= 4:
        return struct.unpack_from('<I', d)[0]
    if typ == REG_QWORD and len(d) >= 8:
        return struct.unpack_from('<Q', d)[0]
    return bytes(d)


def first(v):
    return v[0] if isinstance(v, list) and v else (v if isinstance(v, str) else '')


def epoch(v):
    try:
        return dt.datetime.fromtimestamp(int(v), dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
    except (TypeError, ValueError, OSError, OverflowError):
        return ''


def write_csv(path, rows):
    if not rows:
        return
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description='Feature-update evidence from offline SYSTEM/SOFTWARE hives (thelocalh0st.com)')
    ap.add_argument('system', help='path to a SYSTEM hive')
    ap.add_argument('--software', help='path to the matching SOFTWARE hive (current build and InstallDate)')
    ap.add_argument('-o', '--out', default='upgrade_evidence', help='output folder')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    sysh = Hive(a.system)
    say = print
    say('  upgrade_hive.py | %s | header written %s%s' % (os.path.basename(a.system), sysh.written,
                                                           ' | DIRTY: replay .LOG1/.LOG2 first' if sysh.dirty else ''))
    root = sysh.root
    sel = root.subkey('Select')
    cur = (sel.values().get('Current') if sel else None) or 1
    cs = root.subkey('ControlSet%03d' % cur)
    setup = root.subkey('Setup')

    # 1. upgrade history -------------------------------------------------------------
    hist = []
    for k in (setup.subkeys() if setup else []):
        m = re.match(r'Source OS \(Updated on (.+)\)', k.name)
        if not m:
            continue
        v = k.values()
        hist.append({'OldBuild': '%s.%s' % (v.get('CurrentBuild', '?'), v.get('UBR', '?')), 'OldVersion': v.get('DisplayVersion') or v.get('ReleaseId', ''),
                     'OldProductName': v.get('ProductName', ''), 'OldInstallDateUtc': epoch(v.get('InstallDate')),
                     'OldInstallTimeUtc': filetime(v.get('InstallTime') or 0), 'UpgradeStartedLocal': m.group(1),
                     'KeyLastWriteUtc': k.last_write, 'BuildLabEx': v.get('BuildLabEx', ''), 'RegisteredOwner': v.get('RegisteredOwner', '')})
    hist.sort(key=lambda r: r['OldInstallDateUtc'])
    cur_build = cur_install = ''
    if a.software:
        cv = Hive(a.software).root.path(r'Microsoft\Windows NT\CurrentVersion')
        if cv:
            v = cv.values()
            cur_build = '%s.%s (%s)' % (v.get('CurrentBuild'), v.get('UBR'), v.get('DisplayVersion', ''))
            cur_install = epoch(v.get('InstallDate'))
    for i, r in enumerate(hist):
        nxt = hist[i + 1] if i + 1 < len(hist) else None
        r['NewBuild'] = nxt['OldBuild'] if nxt else cur_build
        r['NewInstallDateUtc'] = nxt['OldInstallDateUtc'] if nxt else cur_install
        r['Kind'] = 'same build (repair / reinstall)' if r['NewBuild'].split('.')[0] == r['OldBuild'].split('.')[0] else 'feature update'
    write_csv(os.path.join(a.out, 'upgrade_history.csv'), hist)
    say('\n  Upgrade history (%d in-place upgrades)' % len(hist))
    for r in hist:
        say('    %-12s %-5s installed %s -> %-12s began %s local, new OS %s %s' % (
            r['OldBuild'], r['OldVersion'], r['OldInstallDateUtc'][:16], r['NewBuild'].split(' ')[0] or '?', r['UpgradeStartedLocal'],
            (r['NewInstallDateUtc'] or '(add --software)')[:16], '[same build]' if r['Kind'].startswith('same') else ''))
    if hist:
        say('    first install on record: %s  (key LastWrite times are reset by each upgrade: %s)' % (hist[0]['OldInstallDateUtc'], hist[-1]['KeyLastWriteUtc']))
    sv = setup.values() if setup else {}
    if sv.get('CloneTag'):
        say('    CloneTag (image build): %s' % first(sv.get('CloneTag')))

    # 2. DeviceMigration ----------------------------------------------------------------
    rows = []
    sources = [('Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration', setup.path(r'Upgrade\PnP\CurrentControlSet\Control\DeviceMigration') if setup else None),
               ('ControlSet%03d\\Control\\DeviceMigration' % cur, cs.path(r'Control\DeviceMigration') if cs else None)]
    enum = cs.subkey('Enum') if cs else None
    for label, dm in sources:
        if not dm:
            continue
        mt = dm.values().get('MigrationTime')
        mtime = filetime(struct.unpack_from('<Q', mt)[0]) if isinstance(mt, bytes) and len(mt) >= 8 else ''
        devs = dm.subkey('Devices')
        for e in (devs.subkeys() if devs else []):
            live_e = enum.subkey(e.name) if enum else None
            for d in e.subkeys():
                live_d = live_e.subkey(d.name) if live_e else None
                for inst in d.subkeys():
                    v = inst.values()
                    vid = re.search(r'VID_([0-9A-F]{4})', d.name, re.I)
                    sub = inst.subkey('Instance')
                    lp = v.get('LastPresentDate')
                    rows.append({'Snapshot': label, 'MigrationTimeUtc': mtime, 'Enumerator': e.name, 'DeviceId': d.name, 'Instance': inst.name,
                                 'Description': v.get('BusDeviceDesc', ''),
                                 'LastPresentUtc': filetime(struct.unpack_from('<Q', lp)[0]) if isinstance(lp, bytes) and len(lp) >= 8 else '',
                                 'Vendor': VENDORS.get(vid.group(1).upper(), '') if vid else '',
                                 'SerialLike': 'yes' if '&' not in inst.name and e.name in ('USB', 'USBSTOR', 'SCSI') else '',
                                 'PresentAtUpgrade': v.get('Present', ''), 'OnlyInSnapshot': '' if not enum else ('no' if (live_d and live_d.subkey(inst.name)) else 'YES'),
                                 'ClassGuid': v.get('ClassGuid', ''), 'DriverInf': v.get('DriverInfName', ''), 'HardwareId': first(v.get('HardwareIds')),
                                 'LocationPath': first(v.get('LocationPaths')), 'ParentIdPrefix': (sub.values().get('ParentIdPrefix', '') if sub else ''),
                                 'KeyLastWriteUtc': inst.last_write})
    write_csv(os.path.join(a.out, 'device_migration.csv'), rows)
    say('\n  DeviceMigration')
    for label, _ in sources:
        r = [x for x in rows if x['Snapshot'] == label]
        if r:
            only = [x for x in r if x['OnlyInSnapshot'] == 'YES']
            say('    %s: %d instances, snapshot %s, %d not present at upgrade, %d only in the snapshot' % (
                label, len(r), r[0]['MigrationTimeUtc'], sum(1 for x in r if x['PresentAtUpgrade'] == 0), len(only)))
            lpd = sorted([x for x in r if x['LastPresentUtc'] and x['Enumerator'] in ('USB', 'USBSTOR', 'SCSI', 'BTHENUM', 'WPDBUSENUM', 'STORAGE', 'SWD')],
                         key=lambda x: x['LastPresentUtc'], reverse=True)
            say('      %d carry LastPresentDate, i.e. when a disconnected device was last seen:' % sum(1 for x in r if x['LastPresentUtc']))
            for x in lpd[:14]:
                say('      last present %s  %-8s %-28s %-14s %s' % (x['LastPresentUtc'][:16], x['Enumerator'], x['DeviceId'][:28], x['Vendor'][:14], x['Description']))
        else:
            say('    %s: not in this hive (or empty)' % label)

    # 3. old app inventory ---------------------------------------------------------------
    apps = []
    ax = setup.path(r'Upgrade\Appx\Applications') if setup else None
    for k in (ax.subkeys() if ax else []):
        for full in k.subkeys():
            apps.append({'PackageFamily': k.name, 'PackageFullName': full.name})
    write_csv(os.path.join(a.out, 'upgrade_apps.csv'), apps)
    say('\n  Setup\\Upgrade\\Appx: %d app packages from the old OS' % len(apps))
    say('\n  CSVs written to %s' % os.path.abspath(a.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
