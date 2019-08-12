# `prismy-session-strategy-jwt-cookie`

JWT cookie session strategy for prismy

[![Build Status](https://travis-ci.com/prismyland/prismy-session-strategy-jwt-cookie.svg?branch=master)](https://travis-ci.com/prismyland/prismy-session-strategy-jwt-cookie)
[![codecov](https://codecov.io/gh/prismyland/prismy-session-strategy-jwt-cookie/branch/master/graph/badge.svg)](https://codecov.io/gh/prismyland/prismy-session-strategy-jwt-cookie)
[![NPM download](https://img.shields.io/npm/dm/prismy-session-strategy-jwt-cookie.svg)](https://www.npmjs.com/package/prismy-session-strategy-jwt-cookie)
[![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/prismyland/prismy-session-strategy-jwt-cookie.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/prismyland/prismy-session-strategy-jwt-cookie/context:javascript)

```
npm i prismy-session prismy-cookie prismy-session-strategy-jwt-cookie
```

## Example

```ts
import {
  prismy,
  methodSelector,
  createUrlEncodedBodySelector,
  redirect,
  res
} from 'prismy'
import createSession from 'prismy-session'
import JWTCookieStrategy from 'prismy-session-strategy-jwt-cookie'

const { sessionSelector, sessionMiddleware } = createSession(
  new JWTCookieStrategy({
    secret: 'RANDOM_HASH'
  })
)

const urlEncodedBodySelector = createUrlEncodedBodySelector()

export default prismy(
  [methodSelector, sessionSelector, urlEncodedBodySelector],
  (method, session, body) => {
    if (method === 'POST') {
      session.data = { message: body.message }
      return redirect('/')
    } else {
      const { data } = session
      return res(
        [
          '<!DOCTYPE html>',
          '<body>',
          `<p>Message: ${data != null ? (data as any).message : 'NULL'}</p>`,
          '<form action="/" method="post">',
          '<input name="message">',
          '<button type="submit">Send</button>',
          '</form>',
          '</body>'
        ].join('')
      )
    }
  },
  [sessionMiddleware]
)
```
