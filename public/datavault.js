class Datavault {
    constructor(apiKey, baseUrl = 'https://datavault-backend-5viv.onrender.com') {
        this.apiKey = apiKey
        this.baseUrl = baseUrl
        this.token = null
    }

    async login(email, password) {
        const res = await fetch(`${this.baseUrl}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        })
        const data = await res.json()
        if (res.ok) {
            this.token = data.token
            localStorage.setItem('dv_token', data.token)
        }
        return data
    }

    autoAuth() {
        this.token = localStorage.getItem('dv_token')
        return this
    }

    from(table) {
        const self = this
        return {
            async select(filter = null, limit = null) {
                let url = `${self.baseUrl}/api/${table}/select`
                if (filter) url += `?filter=${JSON.stringify(filter)}`
                if (limit) url += `${filter ? '&' : '?'}limit=${limit}`
                const res = await fetch(url, { headers: self._headers() })
                return res.json()
            },
            async insert(data) {
                const res = await fetch(`${self.baseUrl}/api/${table}/insert`, {
                    method: 'POST',
                    headers: self._headers(),
                    body: JSON.stringify(data)
                })
                return res.json()
            },
            async update(filter, data) {
                const res = await fetch(`${self.baseUrl}/api/${table}/update`, {
                    method: 'PATCH',
                    headers: self._headers(),
                    body: JSON.stringify({ filter, data })
                })
                return res.json()
            },
            async delete(filter) {
                const res = await fetch(`${self.baseUrl}/api/${table}/delete`, {
                    method: 'DELETE',
                    headers: self._headers(),
                    body: JSON.stringify({ filter })
                })
                return res.json()
            }
        }
    }

    async createTable(name, columns) {
        const res = await fetch(`${this.baseUrl}/api/table/create`, {
            method: 'POST',
            headers: this._headers(),
            body: JSON.stringify({ table_name: name, columns })
        })
        return res.json()
    }

    async uploadFile(file) {
        const formData = new FormData()
        formData.append('file', file)
        const res = await fetch(`${this.baseUrl}/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'x-api-key': this.apiKey
            },
            body: formData
        })
        return res.json()
    }

    _headers() {
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`,
            'x-api-key': this.apiKey
        }
    }
}