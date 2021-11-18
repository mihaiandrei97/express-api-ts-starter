import express from 'express'
import users from './users/users.controller'

const router = express.Router()

router.get('/', (req, res) => {
  res.json({
    message: 'API - 👋🌎🌍🌏',
  })
})

router.use('/users', users)

export default router
