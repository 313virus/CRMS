"""Small compatibility layer for the project's existing SQLite-style queries."""
import re
import psycopg
from psycopg import IntegrityError as PgIntegrityError
from psycopg.rows import dict_row

class DbRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)

class Result:
    def __init__(self, cursor, lastrowid=None):
        self.cursor = cursor
        self.lastrowid = lastrowid
    def fetchone(self):
        row = self.cursor.fetchone()
        return DbRow(row) if row is not None else None
    def fetchall(self):
        return [DbRow(row) for row in self.cursor.fetchall()]
    def __iter__(self):
        return iter(self.fetchall())

class PostgresConnection:
    def __init__(self, url):
        self.conn = psycopg.connect(url, row_factory=dict_row, connect_timeout=15)
    def execute(self, query, params=None):
        if isinstance(params, dict):
            query = re.sub(r':([A-Za-z_][A-Za-z0-9_]*)', r'%(' + r'\1' + r')s', query)
        else:
            query = query.replace('?', '%s')
        insert = bool(re.match(r'^\s*INSERT\s+INTO\s+', query, re.I))
        returning = insert and 'RETURNING' not in query.upper()
        if returning:
            query = query.rstrip().rstrip(';') + ' RETURNING id'
        cursor = self.conn.execute(query, params)
        lastrowid = None
        if returning:
            row = cursor.fetchone()
            lastrowid = row['id']
        return Result(cursor, lastrowid)
    def executemany(self, query, params):
        return self.conn.executemany(query.replace('?', '%s'), params)
    def executescript(self, sql):
        # This file contains only simple CREATE TABLE / CREATE INDEX statements.
        for statement in sql.split(';'):
            if statement.strip():
                self.conn.execute(statement)
    def commit(self):
        self.conn.commit()
    def rollback(self):
        self.conn.rollback()
    def close(self):
        self.conn.close()
