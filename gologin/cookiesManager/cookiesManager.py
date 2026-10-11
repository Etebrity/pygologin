import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import List, Dict, Tuple

from .cookie_database import (
    chromium_to_unix, malformed, repair_database, unix_to_chromium,
)

MAX_SQLITE_VARIABLES = 1
SAME_SITE = {-1: 'unspecified', 0: 'no_restriction', 1: 'lax', 2: 'strict'}
COOKIE_ROW_COLUMN_NAMES = [
    'creation_utc', 'top_frame_site_key', 'host_key', 'name', 'value',
    'encrypted_value', 'path', 'expires_utc', 'is_secure', 'is_httponly',
    'last_access_utc', 'has_expires', 'is_persistent', 'priority', 'samesite',
    'source_scheme', 'source_port', 'is_same_party', 'last_update_utc',
    'source_type', 'has_cross_site_ancestor',
]


class CookiesManager:
    def __init__(self, *args, **kwargs):
        self.profile_id = kwargs.get('profile_id')
        self.tmpdir = kwargs.get('tmpdir')

    def _cookie_paths(self):
        root = Path(self.tmpdir) / ('gologin_' + self.profile_id) / 'Default'
        return root / 'Network' / 'Cookies', root / 'Cookies'

    def _ensure_directory_exists(self, file_path):
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)

    def get_db(self, file_path=None):
        return sqlite3.connect(file_path or self.get_cookies_file_path())

    def create_db_file(self, cookies_file_path, cookies_file_second_path=None,
                       create_cookies_table_query=None):
        # Never truncate an existing profile database, even if an import fails.
        self._ensure_directory_exists(cookies_file_path)
        with closing(self.get_db(cookies_file_path)) as db, db:
            if not db.execute('PRAGMA table_info(cookies)').fetchall():
                if not create_cookies_table_query:
                    raise ValueError('A cookie table schema is required for a new database')
                db.execute(create_cookies_table_query)
        self._repair_file(cookies_file_path)
        if cookies_file_second_path and not Path(cookies_file_second_path).exists():
            self._ensure_directory_exists(cookies_file_second_path)
            with closing(self.get_db(cookies_file_path)) as source:
                with closing(self.get_db(cookies_file_second_path)) as target:
                    source.backup(target)

    def _repair_file(self, path):
        backup = Path(self.tmpdir) / 'cookie-repair-backups' / self.profile_id
        return repair_database(path, backup)

    def repair_cookies(self):
        """Repair downloaded profiles while Chromium is still closed."""
        return {str(path): self._repair_file(path)
                for path in self._cookie_paths() if path.exists()}

    def _insert_row(self, cookie):
        created = cookie.get('creationDate') or time.time()
        if created < 1000000000000000:
            created = self.unix_to_ldap(created)
        elif malformed(created):
            created //= 10
        expiry = 0 if cookie.get('session') else self.unix_to_ldap(cookie.get('expirationDate', 0))
        if cookie.get('domain') == '.mail.google.com' and cookie['name'] == 'COMPASS':
            expiry = 0
        secure = bool(cookie.get('secure') or cookie['name'].startswith(('__Host-', '__Secure-')))
        return dict(
            creation_utc=int(created), host_key=cookie.get('domain', ''),
            top_frame_site_key=cookie.get('topFrameSiteKey') or '', name=cookie['name'],
            value='', encrypted_value=cookie['value'], path=cookie.get('path') or '/',
            expires_utc=expiry, is_secure=int(secure), is_httponly=int(bool(cookie.get('httpOnly'))),
            last_access_utc=int(created), has_expires=int(bool(expiry)), is_persistent=int(bool(expiry)),
            priority=1, samesite=next((k for k, v in SAME_SITE.items() if v == cookie.get('sameSite')), -1),
            source_scheme=cookie.get('sourceScheme', 2 if secure else 1),
            source_port=cookie.get('sourcePort', 443 if secure else 80),
            is_same_party=0, last_update_utc=int(created), source_type=0,
            has_cross_site_ancestor=int(bool(cookie.get('hasCrossSiteAncestor'))),
        )

    def get_chunked_insert_values(self, cookies_arr: List[dict], columns=None) -> List[Tuple[str, List]]:
        names = [name for name in COOKIE_ROW_COLUMN_NAMES if columns is None or name in columns]
        query = 'INSERT INTO cookies (' + ','.join(names) + ') VALUES (' + ','.join('?' for _ in names) + ')'
        return [(query, [tuple(row[name] for name in names)])
                for row in (self._insert_row(cookie) for cookie in cookies_arr)]

    def load_cookies_from_file(self, cookies_file_path=None, is_second_try=False) -> List[Dict]:
        path = Path(cookies_file_path or self.get_cookies_file_path())
        if not path.exists():
            return []
        # An existing Network DB is authoritative, even if empty. Do not fall
        # back to a stale legacy DB or rely on Chromium's column order.
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
            db.row_factory = sqlite3.Row
            cookies = []
            for row in db.execute('SELECT * FROM cookies'):
                data = dict(row)
                cookies.append({
                    'url': self.build_cookie_url(data['host_key'], data['is_secure'], data['path']),
                    'domain': data['host_key'], 'name': data['name'],
                    'value': data['encrypted_value'], 'path': data['path'],
                    'sameSite': SAME_SITE.get(data['samesite'], 'unspecified'),
                    'secure': bool(data['is_secure']), 'httpOnly': bool(data['is_httponly']),
                    'hostOnly': not data['host_key'].startswith('.'),
                    'session': not data['is_persistent'],
                    'expirationDate': self.ldap_to_unix(data['expires_utc']),
                    'creationDate': self.ldap_to_unix(data['creation_utc']),
                    'topFrameSiteKey': data.get('top_frame_site_key') or '',
                    'hasCrossSiteAncestor': bool(data.get('has_cross_site_ancestor')),
                    'sourceScheme': data.get('source_scheme', 0),
                    'sourcePort': data.get('source_port', -1),
                })
            return cookies

    def get_unique_cookies(self, cookies_arr: List[Dict]) -> List[Dict]:
        def identity(cookie):
            return (cookie.get('domain', ''), cookie.get('name', ''),
                    cookie.get('path') or '/', cookie.get('topFrameSiteKey') or '')
        existing = {identity(cookie) for cookie in self.load_cookies_from_file()}
        result = []
        for cookie in cookies_arr:
            key = identity(cookie)
            if key not in existing:
                result.append(cookie)
                existing.add(key)
        return result

    def unix_to_ldap(self, unixtime):
        # Historical method name retained for compatibility. Chromium uses
        # microseconds since 1601, not Windows FILETIME's 100 ns ticks.
        return unix_to_chromium(unixtime)

    def ldap_to_unix(self, ldap):
        return chromium_to_unix(ldap)

    def build_cookie_url(self, domain, secure, path):
        return ('https://' if secure else 'http://') + domain.lstrip('.') + path

    def chunk(self, arr, chunk_size=1):
        return [arr[i:i + chunk_size] for i in range(0, len(arr), chunk_size)] if chunk_size > 0 else []

    def get_cookies_file_path(self):
        network, legacy = self._cookie_paths()
        return str(network if network.exists() or not legacy.exists() else legacy)

    def write_cookies_to_file(self, cookies, is_second_time=False, cookies_table_query=None):
        path = self.get_cookies_file_path()
        if not Path(path).exists():
            self.create_db_file(path, create_cookies_table_query=cookies_table_query)
        self._repair_file(path)
        decoded = []
        for cookie in cookies:
            value = cookie['value']
            if isinstance(value, dict) and isinstance(value.get('data'), list):
                value = bytes(value['data'])
            elif not isinstance(value, bytes):
                raise ValueError('Expected an encrypted cookie buffer')
            decoded.append({**cookie, 'value': value})
        unique = self.get_unique_cookies(decoded)
        with closing(self.get_db(path)) as db, db:
            columns = {row[1] for row in db.execute('PRAGMA table_info(cookies)')}
            for query, parameters in self.get_chunked_insert_values(unique, columns):
                db.executemany(query, parameters)
        # Do not copy a legacy DB over Network/Cookies, nor recreate either
        # database after an SQL error. Preserve metadata, indexes and values.
