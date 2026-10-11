from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from gologin import GoLogin
from gologin.cookiesManager import CookiesManager
from gologin.cookiesManager.cookie_database import chromium_to_unix, repair_database, unix_to_chromium
from unittest.mock import Mock, patch


SCHEMA = '''CREATE TABLE cookies (
    creation_utc INTEGER, host_key TEXT, top_frame_site_key TEXT,
    has_cross_site_ancestor INTEGER, name TEXT, value TEXT, encrypted_value BLOB,
    path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER,
    last_access_utc INTEGER, has_expires INTEGER, is_persistent INTEGER,
    priority INTEGER, samesite INTEGER, source_scheme INTEGER, source_port INTEGER,
    last_update_utc INTEGER)'''


class CookieTests(unittest.TestCase):
    def test_timestamp_units_and_session_zero(self):
        seconds = 1813243011.125
        expected = 13457716611125000
        self.assertEqual(unix_to_chromium(seconds), expected)
        self.assertEqual(unix_to_chromium(seconds * 1000), expected)
        self.assertEqual(chromium_to_unix(expected), seconds)
        self.assertEqual(unix_to_chromium(0), 0)
        self.assertEqual(chromium_to_unix(0), 0)

    def test_repair_prefers_native_cookie_and_preserves_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Cookies'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute(SCHEMA)
                for created, ancestor, value, partition in [
                    (134362038390000000, None, b'old', ''),
                    (13436204538158696, 1, b'fresh', ''),
                    (13436204538158697, 1, b'partitioned', 'https://example.com'),
                ]:
                    db.execute('INSERT INTO cookies (creation_utc,host_key,top_frame_site_key,'
                               'has_cross_site_ancestor,name,encrypted_value,path,expires_utc,'
                               'source_scheme,source_port) VALUES (?,?,?,?,?,?,?,?,?,?)',
                               (created, '.google.com', partition, ancestor, 'SID', value,
                                '/', created, 2, 443))
            report = repair_database(path, Path(directory) / 'backups')
            self.assertEqual(report['removed'], 1)
            with closing(sqlite3.connect(path)) as db, db:
                self.assertEqual({row[0] for row in db.execute('SELECT encrypted_value FROM cookies')},
                                 {b'fresh', b'partitioned'})
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute('INSERT INTO cookies SELECT * FROM cookies LIMIT 1')
            backup = next((Path(directory) / 'backups').iterdir())
            with closing(sqlite3.connect(backup)) as db, db:
                self.assertEqual(db.execute('SELECT count(*) FROM cookies').fetchone()[0], 3)
            self.assertEqual(repair_database(path, Path(directory) / 'backups'),
                             {'removed': 0, 'normalized': 0})

    def test_import_and_upload_use_named_columns_and_keep_saved_cookie(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gologin_test' / 'Default' / 'Network' / 'Cookies'
            path.parent.mkdir(parents=True)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute(SCHEMA)
            gl = object.__new__(GoLogin)
            gl.profile_path = str(Path(directory) / 'gologin_test')
            gl.tmpdir = directory
            gl.profile_id = 'test'
            gl.profile = {'cookies': {'cookies': [dict(
                domain='.google.com', name='SID', path='/', value={'data': [1, 2, 3]},
                expirationDate=1813243011.0, secure=True, sameSite='lax', session=False)]}}
            gl.downloadCookies()
            with closing(sqlite3.connect(path)) as db, db:
                row = db.execute('SELECT creation_utc,expires_utc,encrypted_value FROM cookies').fetchone()
                self.assertLess(row[0], 20000000000000000)
                self.assertEqual(row[1], 13457716611000000)
                self.assertEqual(row[2], b'\x01\x02\x03')
            gl.profile['cookies']['cookies'][0]['value'] = {'data': [9]}
            gl.downloadCookies()
            loaded = gl.load_cookies_from_file()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]['value'], {'data': [1, 2, 3]})
            self.assertEqual(loaded[0]['expirationDate'], 1813243011.0)

    def test_lone_import_is_normalized_without_losing_its_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Cookies'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute(SCHEMA)
                db.execute('INSERT INTO cookies (creation_utc,host_key,name,path,encrypted_value,'
                           'expires_utc,source_scheme,source_port) VALUES (?,?,?,?,?,?,?,?)',
                           (134362038390000000, '.google.com', 'SID', '/', b'imported',
                            134577166110000000, 2, 443))
            self.assertEqual(repair_database(path, Path(directory) / 'backups'),
                             {'removed': 0, 'normalized': 1})
            with closing(sqlite3.connect(path)) as db, db:
                row = db.execute('SELECT creation_utc,expires_utc,encrypted_value,'
                                 'has_cross_site_ancestor,top_frame_site_key FROM cookies').fetchone()
                self.assertEqual(row, (13436203839000000, 13457716611000000, b'imported', 0, ''))


    def test_import_failure_preserves_existing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = CookiesManager(profile_id='test', tmpdir=directory)
            path = Path(manager.get_cookies_file_path())
            path.parent.mkdir(parents=True)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute(SCHEMA)
                db.execute('CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER)')
                db.execute("INSERT INTO meta VALUES ('version',24)")
                db.execute("INSERT INTO cookies (creation_utc,host_key,name,path,encrypted_value) "
                           "VALUES (13436204538158696,'.google.com','SID','/',?)", (b'fresh',))
            with self.assertRaises(ValueError):
                manager.write_cookies_to_file([dict(domain='.google.com',name='NEW',value='invalid')])
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT value FROM meta').fetchone()[0],24)
                self.assertEqual(db.execute('SELECT encrypted_value FROM cookies').fetchone()[0],b'fresh')

    def test_network_database_wins_over_stale_legacy_database(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = CookiesManager(profile_id='test', tmpdir=directory)
            network,legacy=manager._cookie_paths()
            for path, value in [(legacy,b'old'),(network,b'fresh')]:
                path.parent.mkdir(parents=True,exist_ok=True)
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute(SCHEMA)
                    db.execute("INSERT INTO cookies (host_key,name,path,encrypted_value,samesite) "
                               "VALUES ('.google.com','SID','/',?,-1)",(value,))
            self.assertEqual(manager.load_cookies_from_file()[0]['value'],b'fresh')
            with closing(sqlite3.connect(network)) as db, db:
                db.execute('DELETE FROM cookies')
            self.assertEqual(manager.load_cookies_from_file(),[])

    def test_startup_repairs_profiles_without_cookie_import(self):
        gl=object.__new__(GoLogin)
        gl.local=True
        gl.profile_path='unused'
        gl.executablePath='orbita'
        gl.tmpdir='unused'
        gl.profile_id='test'
        gl.writeCookiesFromServer=True
        gl.getProfile=Mock(return_value={'storageInfo':{},'cookies':{'userCookies':False}})
        gl.updatePreferences=Mock()
        gl.downloadCookies=Mock()
        with patch('gologin.gologin.CookiesManager') as manager:
            gl.createStartup()
            manager.return_value.repair_cookies.assert_called_once_with()
        gl.downloadCookies.assert_not_called()

    def test_duplicate_imports_and_session_cookie(self):
        with tempfile.TemporaryDirectory() as directory:
            manager=CookiesManager(profile_id='test',tmpdir=directory)
            cookie=dict(domain='.google.com',name='SID',path='/',value={'data':[1,2]},
                        sameSite='lax',session=True,expirationDate=1813243011.0)
            manager.write_cookies_to_file([cookie,cookie],cookies_table_query=SCHEMA)
            rows=manager.load_cookies_from_file()
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['expirationDate'],0)
            self.assertTrue(rows[0]['session'])

    def test_creating_database_does_not_truncate_saved_cookies(self):
        with tempfile.TemporaryDirectory() as directory:
            manager=CookiesManager(profile_id='test',tmpdir=directory)
            path=manager.get_cookies_file_path()
            manager.create_db_file(path,create_cookies_table_query=SCHEMA)
            manager.write_cookies_to_file([dict(domain='.google.com',name='SID',path='/',
                value={'data':[1,2]},sameSite='lax',session=True)])
            manager.create_db_file(path,create_cookies_table_query=SCHEMA)
            self.assertEqual(manager.load_cookies_from_file()[0]['value'],b'\x01\x02')


if __name__ == '__main__':
    unittest.main()
