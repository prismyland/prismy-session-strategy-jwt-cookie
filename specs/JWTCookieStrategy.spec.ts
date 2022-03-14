import test, { ExecutionContext } from 'ava'
import { prismy, res } from 'prismy'
import createSession from 'prismy-session'
import { testHandler } from 'prismy-test'
import got from 'got'
import { CookieJar } from 'tough-cookie'
import { JWTCookieStrategy } from '../src'
import jwt from 'jsonwebtoken'

test('sessionSelector selects session data', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        strategy.serialize({
          message: 'Hello, World!',
        })
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
      json: true,
    })
    t.deepEqual(postResponse.body, {
      message: 'Hello, World!',
    })
  })
})

test('sessionSelector resolves data as null if JWT cookie is invalid(Not JWT)', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        JSON.stringify({
          message: 'Unsigned value',
        })
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionSelector resolves data as null if JWT cookie is invalid(Wrong Secret)', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!',
            },
          },
          'yolo'
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionSelector resolves data as null if JWT cookie is invalid(Expired)', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!',
            },
          },
          'test',
          {
            expiresIn: -1000,
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionSelector resolves data as null if JWT cookie is invalid(Wrong Algorithm)', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!',
            },
          },
          'test',
          {
            algorithm: 'HS512',
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionSelector resolves data as null if JWT cookie is invalid(Wrong Issuer)', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    issuer: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!',
            },
          },
          'test',
          {
            issuer: 'yolo',
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionSelector resolves data as null if JWT cookie is invalid(Wrong Subject)', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    subject: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!',
            },
          },
          'test',
          {
            subject: 'yolo',
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionSelector resolves data as null if JWT cookie is invalid(Wrong Audience)', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    audience: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!',
            },
          },
          'test',
          {
            audience: 'yolo',
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionSelector resolves data as null if JWT cookie is not given', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res(session.data)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign({}, 'test')
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, '')
  })
})

test('sessionMiddleware saves session.data if changed', async (t) => {
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      session.data = {
        message: 'Hello, World!',
      }
      return res('OK')
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    const postResponse = await got.post(url)
    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!',
      },
    })
  })
})

test('sessionMiddleware sets expire date based on maxAge', async (t) => {
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    maxAge: 3600,
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      session.data = {
        message: 'Hello, World!',
      }
      return res('OK')
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    const postResponse = await got.post(url)
    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!',
      },
      expectedOptions: 'Max-Age=3600; Path=/; HttpOnly',
      expectedMaxAge: 3600,
    })
  })
})

test('sessionMiddleware uses a function to determine secure attribute', async (t) => {
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    secure: () => true,
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      session.data = {
        message: 'Hello, World!',
      }
      return res('OK')
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    const postResponse = await got.post(url)
    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!',
      },
      expectedOptions: 'Max-Age=86400; Path=/; HttpOnly; Secure',
    })
  })
})

test('sessionMiddleware touches maxAge if session data exists', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res('OK')
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!',
            },
          },
          'test',
          { expiresIn: 5000 }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })

    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!',
      },
    })
  })
})

test('sessionMiddleware does NOT touch maxAge if session data does not exist', async (t) => {
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      return res('OK')
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    const postResponse = await got.post(url)
    t.is(postResponse.headers['set-cookie'], undefined)
  })
})

test('sessionMiddleware destroys session if changed to null', async (t) => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
  })
  const { sessionSelector, sessionMiddleware } = createSession(strategy)
  const handler = prismy(
    [sessionSelector],
    (session) => {
      session.data = null
      return res('OK')
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        strategy.serialize({
          message: 'Hello, World!',
        })
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.deepEqual(postResponse.headers['set-cookie'], [
      `session=; Max-Age=0; Path=/; HttpOnly`,
    ])
  })
})

function verifyJWTCookie(
  t: ExecutionContext,
  rawCookie: string,
  {
    expectedData,
    secret,
    expectedOptions = 'Max-Age=86400; Path=/; HttpOnly',
    expectedMaxAge = 86400,
  }: {
    secret: string
    expectedData: any
    expectedOptions?: string
    expectedMaxAge?: number
  }
) {
  const matcher = new RegExp(`^session=(.+); ${expectedOptions}$`)
  const match = rawCookie.match(matcher)
  t.not(
    match,
    null,
    `${rawCookie} is not match "session=(.+); ${expectedOptions}"`
  )
  const token = match![1]
  const decodedValue = jwt.verify(token, secret) as any
  t.is(decodedValue.exp - decodedValue.iat, expectedMaxAge)
  t.deepEqual(decodedValue.data, expectedData)
}
