import sqlite3

DB_NAME = "security_coach.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        protocol TEXT,
        timestamp TEXT,
        severity TEXT
    )
    """)
    
    cursor.execute("CREATE TABLE IF NOT EXISTS stats (key TEXT PRIMARY KEY, value INTEGER)")
    # Inicializamos el contador si no existe
    cursor.execute("INSERT OR IGNORE INTO stats (key, value) VALUES ('passwords_generated', 0)")
    conn.commit()
    conn.close()