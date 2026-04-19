require('dotenv').config()

const express = require('express')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const multer = require('multer')
const crypto = require('crypto')
const fs = require('fs')
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3')
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
    forcePathStyle: true  // ✅ Yeh add karo
})

// MULTER
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
})
const upload = multer({ storage })

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

// HOME
app.get('/', (req, res) => {
    res.send('Datavault server chal raha hai 🚀')
})

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

// UPLOAD — Backblaze B2
app.post('/upload', tokenCheck, projectCheck, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'File nahi mili!' })

        console.log('Upload started:', req.file.filename)
        console.log('File size:', req.file.size)

        const fileStream = fs.createReadStream(req.file.path)
        const fileName = req.file.filename

        await s3.send(new PutObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: fileName,
            Body: fileStream,
            ContentType: req.file.mimetype,
            ContentLength: req.file.size
        }))

        console.log('B2 upload successful!')
        fs.unlinkSync(req.file.path)

        const url = `${process.env.B2_ENDPOINT}/${process.env.B2_BUCKET_NAME}/${fileName}`

        await pool.query(
            'INSERT INTO files (user_id, project_id, filename, url) VALUES ($1, $2, $3, $4)',
            [req.user.id, req.project.id, req.file.filename, url]
        )

        res.json({ message: 'File upload ho gayi!', url })
    } catch (err) {
        console.error('UPLOAD ERROR DETAIL:', err)
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
        res.json(result.rows)
    } catch (err) {
        res.status(500).json({ message: 'Files error', error: err.message })
    }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))