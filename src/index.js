import { findRoot } from '@pleasure-js/utils'
import { isValidSession } from './lib/jwt.js'
import { init, sign, verify } from './lib/jwt-token.js'
import { signIn as SignIn } from './lib/jwt-authentication.js'
import qs from 'qs'
import koaJwt from 'koa-jwt'
import fs from 'fs'
// import SessionBlacklist from './lib/session-blacklist.js'

let io

export default {
  name: 'jwt',
  /**
   * @typedef API.JWTConfig
   * @extends {API.ApiConfig}
   * @property {Object} jwt - Configuration for the jwt plugin
   * @property {String} [jwt.authEndpoint=/token] - Endpoint to hit to grab a token
   * @property {String} [jwt.revokeEndpoint=/revoke] - Endpoint to hit for revoking
   * @property {String} [jwt.privateKey=<root>/api/ssl-keys/private.key] - JWT private key
   * @property {String} [jwt.publicKey=<root>/api/ssl-keys/public.key.pub] - JWT public key
   * @property {String} [jwt.cookieName=pleasure_jwt] - Name of the cookie where to store the jwt token
   * @property {Number} [jwt.saltWorkFactor=10] - Iterations used by bcrypt to hash the password
   * @property {TimeUnit} [jwt.sessionLength=[20, 'minutes']] - Session length
   * @property {Array} [jwt.sessionFields=['_id', 'fullName', 'firstName', 'lastName', 'email', 'level']]
   * - Array of fields to be included within the JWT session. Fields not listed here, would not be included.
   * @property {String} [jwt.authEntity=user] - Name of the entity where the method `loginMethod` should be called.
   * The entity provided will be automatically monitored to trigger profile update events.
   * @property {String|Function|Promise.<Object>} jwt.loginMethod=login - Either a `String` representing the
   * `<authEntity>.<loginMethod>` to be called, or a `function` or a `Promise`. Whichever provided will be called
   * passing an `Object` as a parameter. This object contains the credentials given in {@link PleasureClient#login}.
   * The function or Promise must return an object only with the desired user information to be signed in a JWT.
   */
  config: {
    authEndpoint: '/token',
    revokeEndpoint: '/revoke',
    privateKey: 'api/ssl-keys/private.key',
    publicKey: 'api/ssl-keys/public.key.pub',
    cookieName: 'pleasure_jwt',
    saltWorkFactor: 10,
    sessionLength: [20, 'minutes'],
    sessionFields: ['_id', 'fullName', 'firstName', 'lastName', 'email', 'level'],
    authEntity: 'user',
    loginMethod: 'login' // will trigger user.login(/* http POST payload */)
  },
  methods: {
    isValidSession,
    verify,
    sign
  },
  init ({ mongooseApi, config, pluginsApi: { io: { socketIo } } }) {
    io = socketIo()
    // todo: enable session blacklist
    // SessionBlacklist(mongooseApi)
    init(config) // load ssh keys
    // todo: attach on schemas event and look for the authEntity
  },
  schemaCreated ({ config: { authEntity }, pluginsApi: { io: { socketIo } }, entityName, mongooseSchema }) {
    if (authEntity !== entityName) {
      return
    }

    mongooseSchema.post('save', function (entry) {
      socketIo().to(`$user-${ entry._id }`).emit('profile-update', entry.toObject())
    })
  },
  prepare ({ getEntities, router, config }) {
    const { revokeEndpoint, loginMethod, authEntity, authEndpoint, publicKey, cookieName, sessionFields, sessionLength } = config
    const signIn = SignIn.bind(null, sessionFields, sessionLength)

    router.use(koaJwt({
      secret: fs.readFileSync(findRoot(publicKey)),
      cookie: cookieName,
      passthrough: true
    }))

    router.use(async function (ctx, next) {
      const { user } = ctx.state
      ctx.$pleasure.user = user
      return next()
    })

    router.post(revokeEndpoint, async (ctx, next) => {
      /*
      todo:
        - Validate session, then if valid
        - Blacklist session in db
        - Clean cookie
       */
      ctx.$pleasure.res = { ok: 'revoked!' }
      return next()
    })

    router.post(authEndpoint, async (ctx, next) => {
      const { entities } = await getEntities()
      const loginArguments = [ctx.request.body, qs.parse(ctx.request.querystring, { interpretNumericEntities: true }), ctx]

      if (typeof loginMethod === 'function') {
        ctx.$pleasure.res = await signIn(await loginMethod(...loginArguments))
      } else if (typeof loginMethod === 'string') {
        const entity = entities[authEntity]

        if (entity) {
          ctx.$pleasure.res = await signIn(await entity[loginMethod](...loginArguments))
          // todo: log operation
        } else {
          console.error(`authEntity ${ authEntity } not found`)
        }
      }

      return next()
    })
  }
}
