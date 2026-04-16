const Database = require('better-sqlite3')
const db = new Database('datavault.db')

// Users table
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        naam TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`)

// Files table (UPDATED with project_id)
db.exec(`
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        url TEXT NOT NULL,
        project_id INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`)

// Projects table
db.exec(`
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        api_key TEXT UNIQUE,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`)

console.log('Database ready hai! ✅')
module.exports = db