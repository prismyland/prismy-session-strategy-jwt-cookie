import test, { ExecutionContext } from 'ava'
import createSession, { SessionState } from 'prismy-session'
import { testServer } from 'prismy-test-server'
import got from 'got'
import { CookieJar } from 'tough-cookie'
import { JWTCookieStrategy } from '../src'
import jwt from 'jsonwebtoken'

test('JWTCookieStrategy#loadData returns session data', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        strategy.serialize({
          message: 'Hello, World!'
        })
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar,
      json: true
    })
    t.deepEqual(postResponse.body, {
      message: 'Hello, World!'
    })
  })
})

test('JWTCookieStrategy#loadData returns null if session data is invalid(Not JWT)', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        JSON.stringify({
          message: 'Unsigned value'
        })
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#loadData returns null if session data is invalid(Wrong Secret)', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!'
            }
          },
          'yolo'
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#loadData returns null if session data is invalid(Expired)', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!'
            }
          },
          'test',
          {
            expiresIn: -1000
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#loadData returns null if session data is invalid(Wrong Algorithm)', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    algorithm: 'HS256'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!'
            }
          },
          'test',
          {
            algorithm: 'HS512'
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#loadData returns null if session data is invalid(Wrong Issuer)', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    issuer: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!'
            }
          },
          'test',
          {
            issuer: 'yolo'
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#loadData returns null if session data is invalid(Wrong Subject)', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    audience: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!'
            }
          },
          'test',
          {
            subject: 'yolo'
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#loadData returns null if session data is invalid(Wrong Audience)', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    audience: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!'
            }
          },
          'test',
          {
            audience: 'yolo'
          }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#loadData returns null if session data is not defined', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return session.data
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign({}, 'test')
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.is(postResponse.body, '')
  })
})

test('JWTCookieStrategy#finalize saves session.data if changed', async t => {
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      session.data = {
        message: 'Hello, World!'
      }
      return 'OK'
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    const postResponse = await got.post(url)
    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!'
      }
    })
  })
})

test('JWTCookieStrategy#finalize sets expire date based on maxAge', async t => {
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    maxAge: 3600
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      session.data = {
        message: 'Hello, World!'
      }
      return 'OK'
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    const postResponse = await got.post(url)
    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!'
      },
      expectedOptions: 'Max-Age=3600; Path=/; HttpOnly',
      expectedMaxAge: 3600
    })
  })
})

test('JWTCookieStrategy#finalize uses a function to determine secure attribute', async t => {
  const strategy = new JWTCookieStrategy({
    secret: 'test',
    secure: () => true
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      session.data = {
        message: 'Hello, World!'
      }
      return 'OK'
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    const postResponse = await got.post(url)
    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!'
      },
      expectedOptions: 'Max-Age=86400; Path=/; HttpOnly; Secure'
    })
  })
})

test('JWTCookieStrategy#finalize touches maxAge if session data exists', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return 'OK'
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        jwt.sign(
          {
            data: {
              message: 'Hello, World!'
            }
          },
          'test',
          { expiresIn: 5000 }
        )
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })

    verifyJWTCookie(t, postResponse.headers['set-cookie']![0], {
      secret: 'test',
      expectedData: {
        message: 'Hello, World!'
      }
    })
  })
})

test('JWTCookieStrategy#finalize does NOT touch maxAge if session data does not exist', async t => {
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      return 'OK'
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    const postResponse = await got.post(url)
    t.is(postResponse.headers['set-cookie'], undefined)
  })
})

test('JWTCookieStrategy#finalize destroys session if changed to null', async t => {
  const cookieJar = new CookieJar()
  const strategy = new JWTCookieStrategy({
    secret: 'test'
  })
  const { Session, sessionMiddleware } = createSession({
    strategy
  })
  class Handler {
    async handle(@Session() session: SessionState<any>) {
      session.data = null
      return 'OK'
    }
  }

  await testServer([sessionMiddleware, Handler], async url => {
    cookieJar.setCookieSync(
      `session=${encodeURIComponent(
        strategy.serialize({
          message: 'Hello, World!'
        })
      )}; Max-Age=86400; Path=/; HttpOnly`,
      url
    )
    const postResponse = await got.post(url, {
      cookieJar
    })
    t.deepEqual(postResponse.headers['set-cookie'], [
      `session=; Max-Age=0; Path=/; HttpOnly`
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
    expectedMaxAge = 86400
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
