"""Small compatibility layer for the project's existing SQLite-style queries."""
import os
from psycopg_pool import ConnectionPool
import re
import psycopg
from psycopg import IntegrityError as PgIntegrityError
from psycopg.rows import dict_row
from psycopg.pq import TransactionStatus
from threading import Lock

_pool = None
_pool_url = None
_pool_lock = Lock()

def get_pool(url):
    global _pool, _pool_url
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ConnectionPool(
                    conninfo=url,
                    min_size=0,
                    max_size=5,
                    timeout=20,
                    kwargs={"row_factory": dict_row, "connect_timeout": 15},
                    open=True,
                )
                _pool_url = url
    elif url != _pool_url:
        raise ValueError("PostgreSQL connection URL changed after pool initialization")
    return _pool

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
        self._pool = get_pool(url)
        self.conn = self._pool.getconn()
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
        with self.conn.cursor() as cursor:
            cursor.executemany(query.replace('?', '%s'), params)
            return cursor
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
        if self.conn is None:
            return
        conn = self.conn
        self.conn = None
        try:
            if not conn.closed and conn.info.transaction_status != TransactionStatus.IDLE:
                conn.rollback()
        finally:
            self._pool.putconn(conn)