import express from 'express'
import prisma from '../../db'
import * as yup from 'yup'
import { Prisma } from '@prisma/client'
import bcrypt from 'bcrypt'
import { generateTokens } from '../../lib/jwt'
import * as jwt from 'jsonwebtoken'

const router = express.Router()

const schema = yup.object().shape({
  email: yup.string().trim().email().required(),
  password: yup
    .string()
    .min(8)
    .max(200)
    .matches(/[^A-Za-z0-9]/, 'password must contain a special character')
    .matches(/[A-Z]/, 'password must contain an uppercase letter')
    .matches(/[a-z]/, 'password must contain a lowercase letter')
    .matches(/[0-9]/, 'password must contain a number')
    .required(),
})

router.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body

    const createUser: Prisma.UserCreateInput = { email, password }

    await schema.validate(createUser, {
      abortEarly: false,
    })

    const existingUser = await prisma.user.findUnique({
      where: {
        email,
      },
    })
    if (existingUser) {
      const error = new Error('Email already in use')
      res.status(403)
      throw error
    }

    createUser.password = await bcrypt.hash(password, 12)
    const user = await prisma.user.create({
      data: createUser,
    })

    const { accessToken, refreshToken } = generateTokens(user)

    const createRefreshTokenPayload: Prisma.RefreshTokenUncheckedCreateInput = {
      token: refreshToken,
      userId: user.id,
    }

    const savedRefreshToken = await prisma.refreshToken.create({
      data: createRefreshTokenPayload,
    })

    console.log(savedRefreshToken)

    res.json({
      accessToken,
      refreshToken,
    })
  } catch (error) {
    next(error)
  }
})

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body

    const createUser: Prisma.UserCreateInput = { email, password }

    await schema.validate(createUser, {
      abortEarly: false,
    })

    const existingUser = await prisma.user.findUnique({
      where: {
        email,
      },
    })

    if (!existingUser) {
      const error = new Error('Invalid login.')
      res.status(403)
      throw error
    }

    const validPassword = await bcrypt.compare(password, existingUser.password)

    if (!validPassword) {
      const error = new Error('Invalid login.')
      res.status(403)
      throw error
    }

    const { accessToken, refreshToken } = generateTokens(existingUser)

    const createRefreshTokenPayload: Prisma.RefreshTokenUncheckedCreateInput = {
      token: refreshToken,
      userId: existingUser.id,
    }

    const savedRefreshToken = await prisma.refreshToken.create({
      data: createRefreshTokenPayload,
    })

    console.log(savedRefreshToken)

    res.json({
      accessToken,
      refreshToken,
    })
  } catch (error) {
    next(error)
  }
})

router.post('/refresh_token', async (req, res, next) => {
  const { token } = req.body
  try {
    if (!token) {
      res.status(401)
      throw new Error('Token missing')
    }
    let payload: any = null

    console.log(token, typeof token)
    payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET!)

    const user = await prisma.user.findUnique({
      where: {
        id: Number(payload.userId),
      },
    })

    if (!user) {
      res.status(401)
      throw new Error('Not authorized')
    }

    const savedRefreshToken = await prisma.refreshToken.findUnique({
      where: {
        token: token,
      },
    })

    if (!savedRefreshToken) {
      res.status(401)
      throw new Error('Not authorized.')
    }

    if (savedRefreshToken.userId !== payload.userId) {
      res.status(401)
      throw new Error('Not authorized')
    }

    const { accessToken, refreshToken } = generateTokens(user)

    await prisma.refreshToken.update({
      where: { id: savedRefreshToken.id },
      data: { token: refreshToken },
    })

    res.json({
      accessToken,
      refreshToken,
    })
  } catch (error) {
    res.status(401)
    next(error)
  }
})
export default router
