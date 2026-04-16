const express = require('express')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const multer = require('multer')
const path = require('path')
const crypto = require('crypto')
const db = require('./database')

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.static('public'))

// Uploaded files access
app.use('/uploads', express.static('uploads'))

const SECRET = 'datavault-secret-key-123'

// MULTER SETUP
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueName = Date.now() + '-' + file.originalname
        cb(null, uniqueName)
    }
})

const upload = multer({ storage: storage })

// TOKEN CHECK
function tokenCheck(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ message: 'Token nahi hai! Login karo!' })
    }

    try {
        const user = jwt.verify(token, SECRET)
        req.user = user
        next()
    } catch {
        return res.status(401).json({ message: 'Invalid token!' })
    }
}

// PROJECT CHECK
function projectCheck(req, res, next) {
    const apiKey = req.headers['x-api-key']

    if (!apiKey) {
        return res.status(401).json({ message: 'API key missing hai!' })
    }

    const project = db.prepare(
        'SELECT * FROM projects WHERE api_key = ?'
    ).get(apiKey)

    if (!project) {
        return res.status(403).json({ message: 'Invalid API key!' })
    }

    req.project = project
    next()
}

// HOME
app.get('/', (req, res) => {
    res.send('Datavault server chal raha hai 🚀')
})

// REGISTER
app.post('/users', async (req, res) => {
    const { naam, email, password } = req.body
    const encryptedPassword = await bcrypt.hash(password, 10)

    const result = db.prepare(
        'INSERT INTO users (naam, email, password) VALUES (?, ?, ?)'
    ).run(naam, email, encryptedPassword)

    res.json({ message: 'User ban gaya!', id: result.lastInsertRowid })
})

// LOGIN
app.post('/login', async (req, res) => {
    const { email, password } = req.body

    const user = db.prepare(
        'SELECT * FROM users WHERE email = ?'
    ).get(email)

    if (!user) return res.status(404).json({ message: 'User nahi mila!' })

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) return res.status(401).json({ message: 'Password galat hai!' })

    const token = jwt.sign(
        { id: user.id, email: user.email },
        SECRET,
        { expiresIn: '7d' }
    )

    res.json({ message: 'Login ho gaya!', token })
})

// CREATE PROJECT
app.post('/create-project', (req, res) => {
    const { name } = req.body

    if (!name) {
        return res.status(400).json({ message: 'Project ka naam do!' })
    }

    const apiKey = crypto.randomBytes(16).toString('hex')

    db.prepare(
        'INSERT INTO projects (name, api_key) VALUES (?, ?)'
    ).run(name, apiKey)

    res.json({
        message: 'Project create ho gaya ✅',
        api_key: apiKey
    })
})

// FILE UPLOAD
app.post('/upload', tokenCheck, projectCheck, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'Koi file nahi mili!' })
    }

    const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`

    db.prepare(
        'INSERT INTO files (user_id, filename, url, project_id) VALUES (?, ?, ?, ?)'
    ).run(req.user.id, req.file.filename, url, req.project.id)

    res.json({
        message: 'File upload ho gayi!',
        filename: req.file.filename,
        url: url
    })
})

// GET FILES
app.get('/files', tokenCheck, projectCheck, (req, res) => {
    const files = db.prepare(
        'SELECT * FROM files WHERE user_id = ? AND project_id = ?'
    ).all(req.user.id, req.project.id)

    res.json(files)
})

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})