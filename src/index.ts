import { Context } from 'prismy'
import { cookieSelector, CookieSerializeOptions } from 'prismy-cookie'
import { SessionStrategy, SessionState } from 'prismy-session'
import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken'

export interface JWTCookieStrategyOptions {
  name?: string
  secret: string
  secure?: boolean | ((context: Context) => boolean)
  maxAge?: number
  domain?: string
  httpOnly?: boolean
  path?: string
  sameSite?: boolean | 'lax' | 'strict' | 'none'
  algorithm?: string
  issuer?: string
  subject?: string
  audience?: string
}

type DefaultOptionKeys =
  | 'name'
  | 'maxAge'
  | 'httpOnly'
  | 'secure'
  | 'path'
  | 'algorithm'

type InternalCookieStrategyOptions = Required<
  Pick<JWTCookieStrategyOptions, DefaultOptionKeys>
> &
  Omit<JWTCookieStrategyOptions, DefaultOptionKeys>

export class JWTCookieStrategy implements SessionStrategy {
  value?: unknown
  options: InternalCookieStrategyOptions

  constructor(options: JWTCookieStrategyOptions) {
    this.options = {
      name: 'session',
      maxAge: 86400,
      httpOnly: true,
      secure: false,
      path: '/',
      algorithm: 'HS256',
      ...options
    }
  }

  loadData(context: Context): unknown | null {
    const cookieStore = cookieSelector(context)
    const cookie = cookieStore.get()

    if (cookie[this.options.name] == null) return null
    const serializedData = cookie[this.options.name]

    return this.deserialize(serializedData)
  }

  async finalize(context: Context, session: SessionState) {
    if (session.data === session.previousData) {
      if (session.data == null) {
        return
      } else {
        await this.touch(context, session)
        return
      }
    } else {
      if (session.data == null) {
        await this.destroy(context, session)
        return
      } else {
        await this.save(context, session)
        return
      }
    }
  }

  touch(context: Context, session: SessionState) {
    return this.save(context, session)
  }

  async save(context: Context, session: SessionState) {
    const cookieStore = cookieSelector(context)
    cookieStore.set([
      this.options.name,
      this.serialize(session.data),
      this.getCookieOptions(context)
    ])
  }

  destroy(context: Context, session: SessionState) {
    const cookieStore = cookieSelector(context)
    cookieStore.set([
      this.options.name,
      '',
      {
        ...this.getCookieOptions(context),
        maxAge: 0
      }
    ])
  }

  serialize(data: any): string {
    return jwt.sign({ data }, this.options.secret, this.getJWTSignOptions())
  }

  deserialize(token: string): unknown | null {
    try {
      const result = jwt.verify(
        token,
        this.options.secret,
        this.getJWTVerifyOptions()
      ) as { data?: unknown }
      if (result.data == null) return null
      return result.data
    } catch (error) {
      return null
    }
  }

  getCookieOptions(context: Context): CookieSerializeOptions {
    const { secure, maxAge, domain, httpOnly, path, sameSite } = this.options

    return {
      secure: typeof secure === 'boolean' ? secure : secure(context),
      maxAge,
      domain,
      httpOnly,
      path,
      sameSite
    }
  }

  getJWTSignOptions(): SignOptions {
    const options: SignOptions = {
      expiresIn: `${this.options.maxAge}s`,
      algorithm: this.options.algorithm
    }
    this.copyOnlyConfiguredProp('algorithm', this.options, options)
    this.copyOnlyConfiguredProp('issuer', this.options, options)
    this.copyOnlyConfiguredProp('subject', this.options, options)
    this.copyOnlyConfiguredProp('audience', this.options, options)
    return options
  }

  getJWTVerifyOptions(): VerifyOptions {
    const options: VerifyOptions = {
      maxAge: `${this.options.maxAge}s`,
      algorithms: [this.options.algorithm]
    }
    this.copyOnlyConfiguredProp('issuer', this.options, options)
    this.copyOnlyConfiguredProp('subject', this.options, options)
    this.copyOnlyConfiguredProp('audience', this.options, options)
    return options
  }

  copyOnlyConfiguredProp(key: string, source: any, destination: any) {
    if (source[key] != null) {
      destination[key] = source[key]
    }
  }
}

export default JWTCookieStrategy
