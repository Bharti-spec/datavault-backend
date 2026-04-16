const express = require('express')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const multer = require('multer')
const path = require('path')
const db = require('./database')

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.static('public'))

// Uploaded files seedha access karne ke liye
app.use('/uploads', express.static('uploads'))

const SECRET = 'datavault-secret-key-123'

// MULTER SETUP — files kahan save hongi
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        // File ka unique naam — taaki overwrite na ho
        const uniqueName = Date.now() + '-' + file.originalname
        cb(null, uniqueName)
    }
})

const upload = multer({ storage: storage })

// MIDDLEWARE — Token checker
function tokenCheck(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (!token) {
        return res.status(401).json({ message: 'Token nahi hai! Pehle login karo!' })
    }
    try {
        const user = jwt.verify(token, SECRET)
        req.user = user
        next()
    } catch {
        return res.status(401).json({ message: 'Token galat hai!' })
    }
}

// Home page
app.get('/', (req, res) => {
    res.send('Namaste! Datavault ka server chal raha hai! 🚀')
})

// Naya user banao
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
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
    if (!user) return res.status(404).json({ message: 'User nahi mila!' })
    const passwordSahi = await bcrypt.compare(password, user.password)
    if (!passwordSahi) return res.status(401).json({ message: 'Password galat hai!' })
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '7d' })
    res.json({ message: 'Login ho gaya!', token: token })
})

// PROTECTED — Users dekho
app.get('/users', tokenCheck, (req, res) => {
    const users = db.prepare('SELECT id, naam, email, created_at FROM users').all()
    res.json(users)
})

// FILE UPLOAD — Protected
app.post('/upload', tokenCheck, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'Koi file nahi mili!' })
    }

    const url = `http://localhost:3000/uploads/${req.file.filename}`

    // Database mein save karo
    db.prepare(
        'INSERT INTO files (user_id, filename, url) VALUES (?, ?, ?)'
    ).run(req.user.id, req.file.filename, url)

    res.json({
        message: 'File upload ho gayi!',
        filename: req.file.filename,
        url: url
    })
})

// MERI FILES — dekho
app.get('/files', tokenCheck, (req, res) => {
    const files = db.prepare('SELECT * FROM files WHERE user_id = ?').all(req.user.id)
    res.json(files)
})

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
    console.log(`Server chalu ho gaya! Port ${PORT} pe`)
})