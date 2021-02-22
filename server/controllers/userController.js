const bcrypt = require('bcrypt')

module.exports = {
    register: async (req, res) => {
        const db = req.app.get('db')
        const { email, username, password } = req.body
        const foundUser = await db.check_user(email)
        if (foundUser[0]) {
            return res.status(400).send('User already exists. Please login')
        }
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const [newUser] = await db.add_user([email, username, hash])
        req.session.user = {
            userId: newUser.user_id,
            email: newUser.email,
            username: newUser.username
        }
        res.status(200).send(req.session.user)
    },

    login: async (req, res) => {
        const db = req.app.get('db')
        const { email, password } = req.body
        const [foundUser] = await db.check_user(email)
        if (!foundUser) {
            return res.status(401).send('Login failed. Please try again')
        }
        const authenticated = bcrypt.compareSync(password, foundUser.password)
        if(authenticated) {
            req.session.user = {
                userID: foundUser.user_id,
                email: foundUser.email,
                username: foundUser.username
            }
            res.status(200).send(req.session.user)
        } else {
            res.status(401).send('Login failed. Please try again')
        }
    },

    logout: (req, res) => {
        req.session.destory()
        res.sendStatus(200)
    },

    getUserSession: (res, req) => {
        if (req.session.user) {
            res.status(200).send(req.session.user)
        } else {
            res.status(404).send('Please Log In')
        }
    }
}