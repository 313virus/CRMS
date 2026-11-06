"""One-time migration. Run on your PC with DATABASE_URL configured.
Usage: python migrate_sqlite_to_supabase.py --sqlite risk.db
This overwrites destination demo data only with --replace-demo and requires confirmation.
"""
import argparse
import os
import sqlite3
from pathlib import Path
import psycopg

TABLES = ('users', 'assets', 'threats', 'vulnerabilities', 'risks', 'audit_log')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sqlite', default='risk.db')
    ap.add_argument('--replace-demo', action='store_true', help='Replace ALL existing Supabase CRMS records')
    args = ap.parse_args()
    url = os.environ.get('DATABASE_URL')
    if not url:
        ap.error('Set DATABASE_URL in your local PowerShell session first')
    path = Path(args.sqlite)
    if not path.is_file():
        ap.error(f'Cannot find SQLite database: {path}')
    local = sqlite3.connect(f'file:{path.resolve()}?mode=ro', uri=True)
    local.row_factory = sqlite3.Row
    remote = psycopg.connect(url)
    try:
        with remote.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM users')
            count = cur.fetchone()[0]
            if count and not args.replace_demo:
                raise SystemExit('Supabase already has records. Run again with --replace-demo ONLY if you want to overwrite ALL its CRMS data.')
            if count:
                confirm = input('This will DELETE all existing Supabase CRMS data. Type DELETE to confirm: ')
                if confirm != 'DELETE':
                    raise SystemExit('Cancelled')
                cur.execute('TRUNCATE TABLE audit_log, risks, vulnerabilities, threats, assets, users RESTART IDENTITY CASCADE')
            for table in TABLES:
                rows = local.execute(f'SELECT * FROM {table}').fetchall()
                if not rows:
                    print(f'{table}: 0')
                    continue
                columns = list(rows[0].keys())
                names = ', '.join('"' + col + '"' for col in columns)
                placeholders = ', '.join(['%s'] * len(columns))
                stmt = f'INSERT INTO "{table}" ({names}) VALUES ({placeholders})'
                cur.executemany(stmt, [tuple(row[col] for col in columns) for row in rows])
                print(f'{table}: {len(rows)}')
                # Adjust identity counter to highest migrated ID.
                cur.execute('SELECT pg_get_serial_sequence(%s, %s)', (table, 'id'))
                seq = cur.fetchone()[0]
                cur.execute(f'SELECT MAX(id) FROM "{table}"')
                max_id = cur.fetchone()[0]
                if seq and max_id:
                    cur.execute('SELECT setval(%s, %s, true)', (seq, max_id))
            # Migrate locally stored avatar files into database bytes.
            avatars = path.parent / 'profile_pictures'
            for row in local.execute('SELECT id, avatar_filename FROM users WHERE avatar_filename IS NOT NULL'):
                filename = Path(row['avatar_filename']).name
                image = avatars / filename
                if image.is_file():
                    cur.execute('UPDATE users SET avatar_data=%s WHERE id=%s', (image.read_bytes(), row['id']))
        remote.commit()
        print('Migration completed. Existing SQLite file was not modified.')
    except Exception:
        remote.rollback()
        raise
    finally:
        remote.close()
        local.close()

if __name__ == '__main__':
    main()
