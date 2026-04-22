require('dotenv').config()

const express = require('express')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const multer = require('multer')
const crypto = require('crypto')
const fs = require('fs')
const { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3')
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner')
const pool = require('./database')

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.static('public'))

if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads')
}

app.use('/uploads', express.static('uploads'))

const SECRET = 'datavault-secret-key-123'

// Backblaze B2 Client
const s3 = new S3Client({
    endpoint: process.env.B2_ENDPOINT,
    region: 'us-east-005',
    credentials: {
        accessKeyId: process.env.B2_KEY_ID,
        secretAccessKey: process.env.B2_APP_KEY
    },
    forcePathStyle: true
})

// MULTER
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
})
const upload = multer({ storage })

// ===== MIDDLEWARE =====

// TOKEN CHECK
function tokenCheck(req, res, next) {
    try {
        const token = req.headers['authorization']?.split(' ')[1]
        if (!token) return res.status(401).json({ message: 'Token nahi hai!' })
        req.user = jwt.verify(token, SECRET)
        next()
    } catch {
        res.status(401).json({ message: 'Invalid token!' })
    }
}

// PROJECT CHECK
async function projectCheck(req, res, next) {
    try {
        const apiKey = req.headers['x-api-key']
        if (!apiKey) return res.status(401).json({ message: 'API key missing!' })

        const result = await pool.query(
            'SELECT * FROM projects WHERE api_key = $1', [apiKey]
        )

        if (result.rows.length === 0) {
            return res.status(403).json({ message: 'Invalid API key!' })
        }

        req.project = result.rows[0]
        next()
    } catch (err) {
        res.status(500).json({ message: 'Project check error', error: err.message })
    }
}

// Safe table name helper
function safeTable(projectId, tableName) {
    // Only allow letters, numbers, underscore
    const clean = tableName.replace(/[^a-zA-Z0-9_]/g, '')
    return `p${projectId}_${clean}`
}

// ===== HOME =====
app.get('/', (req, res) => {
    res.send('Datavault server chal raha hai 🚀')
})

// ===== AUTH =====

// REGISTER
app.post('/register', async (req, res) => {
    try {
        const { naam, email, password } = req.body
        if (!naam || !email || !password) {
            return res.status(400).json({ message: 'Sab fields fill karo!' })
        }

        const existing = await pool.query(
            'SELECT * FROM users WHERE email = $1', [email]
        )
        if (existing.rows.length > 0) {
            return res.status(400).json({ message: 'User already exists!' })
        }

        const hash = await bcrypt.hash(password, 10)
        const result = await pool.query(
            'INSERT INTO users (naam, email, password) VALUES ($1, $2, $3) RETURNING id',
            [naam, email, hash]
        )

        res.json({ message: 'User ban gaya!', id: result.rows[0].id })
    } catch (err) {
        res.status(500).json({ message: 'Register error', error: err.message })
    }
})

// LOGIN
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body

        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1', [email]
        )
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User nahi mila!' })
        }

        const user = result.rows[0]
        const valid = await bcrypt.compare(password, user.password)
        if (!valid) return res.status(401).json({ message: 'Password galat hai!' })

        const token = jwt.sign(
            { id: user.id, email: user.email },
            SECRET,
            { expiresIn: '7d' }
        )

        res.json({ message: 'Login ho gaya!', token })
    } catch (err) {
        res.status(500).json({ message: 'Login error', error: err.message })
    }
})

// ===== PROJECTS =====

// CREATE PROJECT
app.post('/create-project', async (req, res) => {
    try {
        const { name } = req.body
        if (!name) return res.status(400).json({ message: 'Project ka naam do!' })

        const apiKey = crypto.randomBytes(16).toString('hex')

        await pool.query(
            'INSERT INTO projects (name, api_key) VALUES ($1, $2)',
            [name, apiKey]
        )

        res.json({ message: 'Project create ho gaya ✅', api_key: apiKey })
    } catch (err) {
        res.status(500).json({ message: 'Project error', error: err.message })
    }
})

// GET ALL PROJECTS
app.get('/projects', tokenCheck, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM projects ORDER BY created_at DESC'
        )
        res.json(result.rows)
    } catch (err) {
        res.status(500).json({ message: 'Projects error', error: err.message })
    }
})

// ===== FILE STORAGE =====

// UPLOAD
app.post('/upload', tokenCheck, projectCheck, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'File nahi mili!' })

        const fileStream = fs.createReadStream(req.file.path)
        const fileName = req.file.filename

        await s3.send(new PutObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: fileName,
            Body: fileStream,
            ContentType: req.file.mimetype,
            ContentLength: req.file.size
        }))

        fs.unlinkSync(req.file.path)

        const signedUrl = await getSignedUrl(
            s3,
            new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: fileName
            }),
            { expiresIn: 604800 }
        )

        await pool.query(
            'INSERT INTO files (user_id, project_id, filename, url) VALUES ($1, $2, $3, $4)',
            [req.user.id, req.project.id, req.file.filename, signedUrl]
        )

        res.json({ message: 'File upload ho gayi!', url: signedUrl })
    } catch (err) {
        res.status(500).json({ message: 'Upload error', error: err.message })
    }
})

// GET FILES
app.get('/files', tokenCheck, projectCheck, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM files WHERE user_id = $1 AND project_id = $2',
            [req.user.id, req.project.id]
        )

        const filesWithUrls = await Promise.all(result.rows.map(async (file) => {
            const signedUrl = await getSignedUrl(
                s3,
                new GetObjectCommand({
                    Bucket: process.env.B2_BUCKET_NAME,
                    Key: file.filename
                }),
                { expiresIn: 604800 }
            )
            return { ...file, url: signedUrl }
        }))

        res.json(filesWithUrls)
    } catch (err) {
        res.status(500).json({ message: 'Files error', error: err.message })
    }
})

// DELETE FILE
app.delete('/files/:id', tokenCheck, projectCheck, async (req, res) => {
    try {
        const { id } = req.params

        const result = await pool.query(
            'SELECT * FROM files WHERE id = $1 AND user_id = $2',
            [id, req.user.id]
        )

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'File nahi mili!' })
        }

        const file = result.rows[0]

        await s3.send(new DeleteObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: file.filename
        }))

        await pool.query('DELETE FROM files WHERE id = $1', [id])

        res.json({ message: 'File delete ho gayi! 🗑️' })
    } catch (err) {
        res.status(500).json({ message: 'Delete error', error: err.message })
    }
})

// ===== DATABASE API =====

// List all tables of a project
app.get('/api/tables', tokenCheck, projectCheck, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM dv_tables WHERE project_id = $1 ORDER BY created_at DESC',
            [req.project.id]
        )
        res.json({ tables: result.rows })
    } catch (err) {
        res.status(500).json({ message: 'Error', error: err.message })
    }
})

// Create Table
app.post('/api/table/create', tokenCheck, projectCheck, async (req, res) => {
    try {
        const { table_name, columns } = req.body
        const projectId = req.project.id

        if (!table_name || !columns) {
            return res.status(400).json({ message: 'Table name aur columns do!' })
        }

        const tableName = safeTable(projectId, table_name)

        const colDefs = Object.entries(columns).map(([name, type]) => {
            const pgType = type === 'number' ? 'NUMERIC' :
                          type === 'boolean' ? 'BOOLEAN' :
                          type === 'date' ? 'TIMESTAMP' : 'TEXT'
            return `"${name}" ${pgType}`
        }).join(', ')

        await pool.query(`
            CREATE TABLE IF NOT EXISTS "${tableName}" (
                id SERIAL PRIMARY KEY,
                ${colDefs},
                created_at TIMESTAMP DEFAULT NOW()
            )
        `)

        await pool.query(
            'INSERT INTO dv_tables (project_id, table_name, columns) VALUES ($1, $2, $3) ON CONFLICT (project_id, table_name) DO NOTHING',
            [projectId, table_name, JSON.stringify(columns)]
        )

        res.json({ message: 'Table ban gayi! ✅', table: table_name })
    } catch (err) {
        res.status(500).json({ message: 'Table create error', error: err.message })
    }
})

// Delete Table
app.delete('/api/table/:table_name', tokenCheck, projectCheck, async (req, res) => {
    try {
        const { table_name } = req.params
        const projectId = req.project.id
        const tableName = safeTable(projectId, table_name)

        await pool.query(`DROP TABLE IF EXISTS "${tableName}"`)
        await pool.query(
            'DELETE FROM dv_tables WHERE project_id = $1 AND table_name = $2',
            [projectId, table_name]
        )

        res.json({ message: 'Table delete ho gayi! 🗑️' })
    } catch (err) {
        res.status(500).json({ message: 'Table delete error', error: err.message })
    }
})

// Insert Data
app.post('/api/:table/insert', tokenCheck, projectCheck, async (req, res) => {
    try {
        const { table } = req.params
        const projectId = req.project.id
        const data = req.body

        if (!data || Object.keys(data).length === 0) {
            return res.status(400).json({ message: 'Data do!' })
        }

        const tableName = safeTable(projectId, table)
        const keys = Object.keys(data)
        const values = Object.values(data)
        const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ')
        const colNames = keys.map(k => `"${k}"`).join(', ')

        const result = await pool.query(
            `INSERT INTO "${tableName}" (${colNames}) VALUES (${placeholders}) RETURNING *`,
            values
        )

        res.json({ data: result.rows[0], message: 'Data add ho gaya! ✅' })
    } catch (err) {
        res.status(500).json({ message: 'Insert error', error: err.message })
    }
})

// Select Data
app.get('/api/:table/select', tokenCheck, projectCheck, async (req, res) => {
    try {
        const { table } = req.params
        const projectId = req.project.id
        const { filter, limit, order } = req.query

        const tableName = safeTable(projectId, table)
        let query = `SELECT * FROM "${tableName}"`
        const values = []

        if (filter) {
            const f = JSON.parse(filter)
            const conditions = Object.entries(f).map(([k, v], i) => {
                values.push(v)
                return `"${k}" = $${i + 1}`
            })
            query += ` WHERE ${conditions.join(' AND ')}`
        }

        query += ` ORDER BY created_at ${order === 'asc' ? 'ASC' : 'DESC'}`

        if (limit) query += ` LIMIT ${parseInt(limit)}`

        const result = await pool.query(query, values)
        res.json({ data: result.rows })
    } catch (err) {
        res.status(500).json({ message: 'Select error', error: err.message })
    }
})

// Update Data
app.patch('/api/:table/update', tokenCheck, projectCheck, async (req, res) => {
    try {
        const { table } = req.params
        const projectId = req.project.id
        const { filter, data } = req.body

        if (!data) return res.status(400).json({ message: 'Data do!' })

        const tableName = safeTable(projectId, table)
        const dataKeys = Object.keys(data)
        const dataValues = Object.values(data)

        const setClause = dataKeys.map((k, i) => `"${k}" = $${i + 1}`).join(', ')
        const allValues = [...dataValues]

        let query = `UPDATE "${tableName}" SET ${setClause}`

        if (filter) {
            const filterEntries = Object.entries(filter)
            const filterClause = filterEntries.map(([k, v], i) => {
                allValues.push(v)
                return `"${k}" = $${dataKeys.length + i + 1}`
            })
            query += ` WHERE ${filterClause.join(' AND ')}`
        }

        query += ' RETURNING *'
        const result = await pool.query(query, allValues)
        res.json({ data: result.rows, message: 'Updated! ✅' })
    } catch (err) {
        res.status(500).json({ message: 'Update error', error: err.message })
    }
})

// Delete Data
app.delete('/api/:table/delete', tokenCheck, projectCheck, async (req, res) => {
    try {
        const { table } = req.params
        const projectId = req.project.id
        const { filter } = req.body

        const tableName = safeTable(projectId, table)
        const values = []
        let query = `DELETE FROM "${tableName}"`

        if (filter) {
            const conditions = Object.entries(filter).map(([k, v], i) => {
                values.push(v)
                return `"${k}" = $${i + 1}`
            })
            query += ` WHERE ${conditions.join(' AND ')}`
        }

        query += ' RETURNING *'
        const result = await pool.query(query, values)
        res.json({ data: result.rows, message: 'Deleted! ✅' })
    } catch (err) {
        res.status(500).json({ message: 'Delete error', error: err.message })
    }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))