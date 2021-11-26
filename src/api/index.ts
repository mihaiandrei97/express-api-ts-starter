import express, { Request } from 'express'
import { isAuthenticated, RequestCustomInterface } from '../middlewares'
import auth from './auth/auth.routes'
const router = express.Router()

router.get('/', (req, res) => {
  res.json({
    message: 'API - 👋🌎🌍🌏',
  })
})

router.get(
  '/protected',
  isAuthenticated,
  (req: RequestCustomInterface, res) => {
    console.log(req.payload)
    res.json({
      message: 'Private data - 🔏👋',
    })
  }
)

router.use('/auth', auth)

export default router
