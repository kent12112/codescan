import sqlite3
def get(db, name):
    cur = sqlite3.connect(db).cursor()
    return cur.execute(f"SELECT * FROM users WHERE name='{name}'").fetchall()   # SQL injection
