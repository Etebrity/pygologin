"""Chromium cookie database repair and timestamp conversion."""
from contextlib import closing
import sqlite3
import time
from pathlib import Path


EPOCH_SECONDS = 11644473600
IDENTITY = ('host_key', 'top_frame_site_key', 'has_cross_site_ancestor',
            'name', 'path', 'source_scheme', 'source_port')
TIMESTAMPS = ('creation_utc', 'expires_utc', 'last_access_utc', 'last_update_utc')


def unix_to_chromium(value):
    if not value:
        return 0
    if value > 32503680000:  # Browser exports sometimes use Unix milliseconds.
        value /= 1000
    return int((value + EPOCH_SECONDS) * 1000000)


def chromium_to_unix(value):
    return value / 1000000 - EPOCH_SECONDS if value else 0


def malformed(value):
    # The broken SDK wrote 100 ns ticks, roughly 1.3e17 for present dates.
    return 100000000000000000 <= (value or 0) < 200000000000000000


def repair_database(path, backup_directory):
    """Run only while Chrome is closed. Preserve native cookie identities."""
    path = Path(path)
    if not path.exists():
        return {'removed': 0, 'normalized': 0}
    with closing(sqlite3.connect(path)) as db, db:
        db.row_factory = sqlite3.Row
        columns = {row['name'] for row in db.execute('PRAGMA table_info(cookies)')}
        if not columns:
            raise RuntimeError('Cookie database has no cookies table')
        rows = [dict(row) for row in db.execute('SELECT rowid AS repair_id, * FROM cookies')]
        # Compare imported rows with native rows by the identity available in
        # the export. Import guessed source scheme/port and omitted ancestor.
        base = tuple(c for c in ('host_key', 'top_frame_site_key', 'name', 'path') if c in columns)
        native = {tuple(row[c] for c in base) for row in rows
                  if row.get('creation_utc', 0) > 1000000000000000
                  and not malformed(row.get('creation_utc'))}
        remove = {row['repair_id'] for row in rows
                  if malformed(row.get('creation_utc'))
                  and tuple(row[c] for c in base) in native}
        identity = tuple(c for c in IDENTITY if c in columns)
        winners = {}
        for row in rows:
            if row['repair_id'] in remove:
                continue
            key = tuple((row[c] if row[c] is not None else ('' if c == 'top_frame_site_key' else 0))
                        for c in identity)
            def rank(item):
                return tuple((item.get(c) or 0) // (10 if malformed(item.get(c)) else 1)
                             for c in ('last_update_utc', 'creation_utc', 'last_access_utc')) + (item['repair_id'],)
            if key in winners:
                old = winners[key]
                winner, loser = (row, old) if rank(row) > rank(old) else (old, row)
                remove.add(loser['repair_id'])
                winners[key] = winner
            else:
                winners[key] = row
        normalize = [row for row in rows if row['repair_id'] not in remove
                     and any(malformed(row.get(c)) for c in TIMESTAMPS)]
        nulls = any(any(row[c] is None for c in identity) for row in rows)
        indexes = list(db.execute('PRAGMA index_list(cookies)'))
        indexed = any(row['unique'] and tuple(x['name'] for x in db.execute(
            'PRAGMA index_info("' + row['name'].replace('"', '""') + '")')) == identity for row in indexes)
        if remove or normalize or nulls or not indexed:
            backup_directory = Path(backup_directory)
            backup_directory.mkdir(parents=True, exist_ok=True)
            backup = backup_directory / (str(time.time_ns()) + '-' + path.parent.name + '-Cookies.sqlite')
            with closing(sqlite3.connect(backup)) as target, target:
                db.backup(target)
            for rowid in remove:
                db.execute('DELETE FROM cookies WHERE rowid=?', (rowid,))
            for row in normalize:
                for col in TIMESTAMPS:
                    if col in columns and malformed(row.get(col)):
                        db.execute(f'UPDATE cookies SET {col}=? WHERE rowid=?',
                                   (row[col] // 10, row['repair_id']))
            for col in identity:
                db.execute(f'UPDATE cookies SET {col}=? WHERE {col} IS NULL',
                           ('' if col == 'top_frame_site_key' else 0,))
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS gologin_cookie_unique ON cookies ('
                       + ','.join(identity) + ')')
        return {'removed': len(remove), 'normalized': len(normalize)}
