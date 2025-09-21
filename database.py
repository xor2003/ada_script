import sqlite3
from utils import logger, handle_error  # Assume utils.py with logging

class Database:
    def __init__(self, path='analysis.db'):
        try:
            self.conn = sqlite3.connect(path)
            self._create_tables()
            logger.info(f"DB initialized: {path}")
        except sqlite3.Error as e:
            handle_error(f"DB init failed: {e}", e, fatal=True)
            raise

    def _create_tables(self):
        try:
            cur = self.conn.cursor()
            # Instructions table
            cur.execute("DROP TABLE IF EXISTS instructions")
            cur.execute("""
                CREATE TABLE instructions (
                    addr INTEGER PRIMARY KEY,
                    size INTEGER,
                    mnem TEXT,
                    op_str TEXT,
                    type TEXT DEFAULT 'code'
                )
            """)
            # Functions table
            cur.execute("DROP TABLE IF EXISTS functions")
            cur.execute("""
                CREATE TABLE functions (
                    start INTEGER PRIMARY KEY,
                    end INTEGER,
                    name TEXT
                )
            """)
            # Symbols table (for IDC names)
            cur.execute("DROP TABLE IF EXISTS symbols")
            cur.execute("""
                CREATE TABLE symbols (
                    addr INTEGER PRIMARY KEY,
                    name TEXT
                )
            """)
            # Xrefs table
            cur.execute("DROP TABLE IF EXISTS xrefs")
            cur.execute("""
                CREATE TABLE xrefs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_addr INTEGER NOT NULL,
                    to_addr INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    instruction TEXT,
                    FOREIGN KEY(from_addr) REFERENCES instructions(addr),
                    FOREIGN KEY(to_addr) REFERENCES instructions(addr)
                )
            """)
            # Segments table (enhanced)
            cur.execute("DROP TABLE IF EXISTS segments")
            cur.execute("""
                CREATE TABLE segments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_addr INTEGER NOT NULL,
                    end_addr INTEGER NOT NULL,
                    class TEXT DEFAULT 'UNKNOWN',
                    type TEXT DEFAULT 'code',
                    executable INTEGER DEFAULT 0,
                    entropy REAL DEFAULT 0.0,
                    name TEXT
                )
            """)
            
            # Relocations table
            cur.execute("DROP TABLE IF EXISTS relocations")
            cur.execute("""
                CREATE TABLE relocations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    addr INTEGER NOT NULL,
                    offset INTEGER NOT NULL
                )
            """)
            
            # Comments table
            cur.execute("DROP TABLE IF EXISTS comments")
            cur.execute("""
                CREATE TABLE comments (
                    addr INTEGER PRIMARY KEY,
                    comment TEXT NOT NULL,
                    repeatable INTEGER DEFAULT 0
                )
            """)
            
            # Stats table
            cur.execute("DROP TABLE IF EXISTS stats")
            cur.execute("""
                CREATE TABLE stats (
                    key TEXT PRIMARY KEY,
                    value REAL
                )
            """)
            
            # Processor config
            cur.execute("DROP TABLE IF EXISTS config")
            cur.execute("""
                CREATE TABLE config (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            
            self.conn.commit()
            logger.debug("Tables created/verified")
        except sqlite3.Error as e:
            handle_error(f"Table creation failed: {e}", e)
            raise

    def execute(self, query, params=()):
        try:
            cur = self.conn.cursor()
            cur.execute(query, params)
            self.conn.commit()
            return cur
        except sqlite3.Error as e:
            logger.error(f"DB query failed: {query[:50]}... - {e}")
            if 'CREATE' in query:
                logger.info("Retrying table creation...")
                self._create_tables()
                # Retry once
                try:
                    cur = self.conn.cursor()
                    cur.execute(query, params)
                    self.conn.commit()
                    return cur
                except sqlite3.Error:
                    pass
            raise

    def add_xref(self, from_addr, to_addr, xtype, instruction=''):
        try:
            self.execute("""
                INSERT OR IGNORE INTO xrefs (from_addr, to_addr, type, instruction)
                VALUES (?, ?, ?, ?)
            """, (from_addr, to_addr, xtype, instruction))
        except Exception as e:
            logger.warning(f"Xref add failed {from_addr}->{to_addr}: {e}")

    def get_xrefs_to(self, addr):
        try:
            return self.execute("SELECT * FROM xrefs WHERE to_addr=?", (addr,)).fetchall()
        except Exception as e:
            logger.warning(f"Xref query failed for {hex(addr)}: {e}")
            return []

    def close(self):
        try:
            self.conn.close()
            logger.debug("DB closed")
        except Exception as e:
            logger.warning(f"DB close failed: {e}")