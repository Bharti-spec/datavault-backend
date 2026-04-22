const { Pool } = require('pg')

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
})

async function initDB() {
    // Users table
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            naam TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    `)

    // Projects table
    await pool.query(`
        CREATE TABLE IF NOT EXISTS projects (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    `)

    // Files table
    await pool.query(`
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            url TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    `)

    // Datavault Tables Registry — developer ki tables ka record
    await pool.query(`
        CREATE TABLE IF NOT EXISTS dv_tables (
            id SERIAL PRIMARY KEY,
            project_id INTEGER NOT NULL,
            table_name TEXT NOT NULL,
            columns JSONB,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(project_id, table_name)
        )
    `)

    console.log('Database ready hai! ✅')
}

initDB()
module.exports = pool