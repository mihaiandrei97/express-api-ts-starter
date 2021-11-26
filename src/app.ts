import express, { RequestHandler } from 'express'
import morgan from 'morgan'
import helmet from 'helmet'
import cors from 'cors'

require('dotenv').config()

import { notFound, errorHandler } from './middlewares'
import api from './api'

const app = express()

app.use(morgan('dev'))
app.use(helmet())
app.use(cors())
app.use(express.json())

// app.use(checkTokenSetUser)

app.get('/', (req, res) => {
  res.json({
    message: '🦄🌈✨👋🌎🌍🌏✨🌈🦄',
  })
})

app.use('/api/v1', api)

app.use(notFound)
app.use(errorHandler)

export default app
