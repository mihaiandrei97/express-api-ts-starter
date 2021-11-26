import { Request, Response, NextFunction } from 'express'
import * as jwt from 'jsonwebtoken'
export interface ErrorInterface extends Error {
  errors: string[]
}

export interface RequestCustomInterface extends Request {
  payload?: {
    userId: string
  }
}

export function notFound(req: Request, res: Response, next: NextFunction) {
  res.status(404)
  const error = new Error(`🔍 - Not Found - ${req.originalUrl}`)
  next(error)
}

/* eslint-disable no-unused-vars */
export function errorHandler(
  err: ErrorInterface,
  req: Request,
  res: Response,
  next: NextFunction
) {
  console.log(err.name)
  const statusCode =
    err.name === 'ValidationError'
      ? 400
      : res.statusCode !== 200
      ? res.statusCode
      : 500

  res.status(statusCode)

  res.json({
    status: statusCode,
    message: err.errors ? 'Validation Error' : err.message,
    errors: err.errors,
  })
}

// export function checkTokenSetUser(
//   req: RequestCustomInterface,
//   res: Response,
//   next: NextFunction
// ) {
//   try {
//     const authHeader = req.get('Authorization')
//     console.log(authHeader)
//     if (authHeader) {
//       const token = authHeader.split(' ')[1]
//       if (token) {
//         // https://stackoverflow.com/questions/48662639/node-js-jwt-refresh-token-in-express-middleware
//         const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!)
//         req.payload = payload as any
//         next()
//       } else {
//         next()
//       }
//     } else {
//       next()
//     }
//   } catch (err: any) {
//     if (err.name === 'TokenExpiredError') {
//       res.status(401)
//       throw err
//     } else {
//       next()
//     }
//   }
// }

export function isLoggedIn(
  req: RequestCustomInterface,
  res: Response,
  next: NextFunction
) {
  if (req.payload) {
    next()
  } else {
    unAuthorized(res, next)
  }
}

// function isAdmin(req: Request, res: Response, next: NextFunction) {
//   if (req.user.role === 'admin') {
//     next()
//   } else {
//     unAuthorized(res, next)
//   }
// }

export function unAuthorized(res: Response, next: NextFunction) {
  const error = new Error('🚫 Un-Authorized 🚫')
  res.status(401)
  next(error)
}

export function isAuthenticated(
  req: RequestCustomInterface,
  res: Response,
  next: NextFunction
) {
  const authorization = req.headers['authorization']

  if (!authorization) {
    res.status(401)
    throw new Error('not authenticated')
  }

  try {
    const token = authorization.split(' ')[1]
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!)
    req.payload = payload as any
  } catch (err: any) {
    res.status(401)
    if (err.name === 'TokenExpiredError') {
      throw new Error(err.name)
    }
    throw new Error('not authenticated')
  }

  return next()
}
