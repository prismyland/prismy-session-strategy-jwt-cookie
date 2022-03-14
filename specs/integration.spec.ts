import test from 'ava'
import createSession from 'prismy-session'
import { prismy, methodSelector, res } from 'prismy'
import { testHandler } from 'prismy-test'
import got from 'got'
import { CookieJar } from 'tough-cookie'
import { JWTCookieStrategy } from '../src'

test('integration test', async (t) => {
  const cookieJar = new CookieJar()
  const { sessionSelector, sessionMiddleware } = createSession(
    new JWTCookieStrategy({
      secret: 'test',
    })
  )
  const handler = prismy(
    [methodSelector, sessionSelector],
    (method, session) => {
      if (method === 'POST') {
        session.data = { message: 'Hello, World!' }
        return res('OK')
      }
      const { data } = session
      return res((data as any).message)
    },
    [sessionMiddleware]
  )

  await testHandler(handler, async (url) => {
    const postResponse = await got.post(url, {
      cookieJar,
    })
    t.is(postResponse.body, 'OK')

    const getResponse = await got(url, {
      cookieJar,
      retry: 0,
    })
    t.is(getResponse.body, 'Hello, World!')
  })
})
