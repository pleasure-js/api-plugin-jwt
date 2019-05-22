/*!
 * pleasure-api-plugin-jwt v1.0.0-beta
 * (c) 2018-2019 undefined
 * Released under the MIT License.
 */
import { findRoot } from 'pleasure-utils';
import merge from 'deepmerge';
import pick from 'lodash/pick';
import moment from 'moment';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import hash from 'object-hash';
import { getMongoose } from 'pleasure-api';
import { Schema } from 'mongoose';
import qs from 'qs';
import koaJwt from 'koa-jwt';

function SessionBlacklist () {
  const mongoose = getMongoose();

  const sessionBlacklistSchema = new Schema({
    created: {
      type: Date,
      default: Date.now
    },
    sessionId: {
      type: String,
      required: true,
      unique: true
    },
    expires: {
      type: Date,
      default: Date.now
    },
    sessionExpires: {
      type: Date,
      required: true,
      options: {
        meta: {
          description: `Moment on which the JWT session originally expired`
        }
      }
    }
  }, {
    toObject: {
      virtuals: true
    },
    toJSON: {
      virtuals: true
    }
  });

  return mongoose.model('pleasure-session-blacklist', sessionBlacklistSchema, 'pleasure-session-blacklist')
}

// const { models: { sessionBlacklist: SessionBlacklist } } = getModels()
// const { appLogger } = require('./log')

let jwtCert;
let jwtPub;

let SessionBlacklist$1;

function init (config) {
  SessionBlacklist$1 = SessionBlacklist();

  let { privateKey, publicKey } = config;
  privateKey = findRoot(privateKey);
  publicKey = findRoot(publicKey);

  if (!fs.existsSync(privateKey) || !fs.existsSync(publicKey)) {
    console.error('Please generate server keys first.');
    process.exit(0);
  }

  jwtCert = fs.readFileSync(privateKey); // get private key
  jwtPub = fs.readFileSync(publicKey); // get private key
}

function sign (what, cert) {
  return new Promise((resolve, reject) => {
    jwt.sign(what, cert || jwtCert, { algorithm: 'RS256' }, function (err, token) {
      if (err) {
        return reject(new Error(err))
      }

      resolve(token);
    });
  })
}

function verify (token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, jwtPub, function (err, decoded) {
      if (err) {
        return reject(new Error(err))
      }

      resolve(decoded);
    });
  })
}

async function isRevoked (sessionId) {
  const blacklist = await SessionBlacklist$1.findOne({ sessionId });
  return blacklist && moment().isAfter(moment(blacklist.expires))
}

async function isValidSession (token) {
  let user;
  try {
    user = await verify(token);
  } catch (err) {
    return false
  }

  return !(!user || user.expires <= Date.now() || await isRevoked(user.sessionId))
}

async function jwtSession (data, sessionExpires, sessionLength = []) {
  sessionExpires = sessionExpires || moment().add(...sessionLength).valueOf();

  const userSession = merge(data, {
    sessionExpires
  });

  const sessionId = hash(userSession, { ignoreUnknown: true });
  const refreshToken = await sign(sessionId);
  const accessToken = await sign(merge(userSession, { sessionId }));

  if (accessToken.length > 4096) {
    console.error(`Resulted token can't be stored as a cookie since it exceeds the limit of 4096 bytes (current size: ${accessToken.length} bytes)`);
  }

  return { accessToken, refreshToken, sessionId }
}

async function signIn (sessionFields = [], sessionLength = [], user) {
  // object-hash for some reason is having troubles encoding the ObjectId
  if (user._id) {
    user._id = user._id.toString();
  }

  return pick(await jwtSession(pick(user, sessionFields)), ['accessToken', 'refreshToken'], sessionLength)
}

let io;

var index = {
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
  init ({ config, pluginsApi: { io: { socketIo } } }) {
    console.log('initializing jwt');
    io = socketIo();
    init(config); // load ssh keys
    // todo: attach on schemas event and look for the authEntity
  },
  schemaCreated ({ config: { authEntity }, pluginsApi: { io: { socketIo } }, entityName, mongooseSchema }) {
    if (authEntity !== entityName) {
      return
    }

    mongooseSchema.post('save', function (entry) {
      socketIo().to(`$user-${ entry._id }`).emit('profile-update', entry.toObject());
    });
  },
  prepare ({ getEntities, router, config }) {
    const { revokeEndpoint, loginMethod, authEntity, authEndpoint, publicKey, cookieName, sessionFields, sessionLength } = config;
    const signIn$1 = signIn.bind(null, sessionFields, sessionLength);

    router.use(koaJwt({
      secret: fs.readFileSync(findRoot(publicKey)),
      cookie: cookieName,
      passthrough: true
    }));

    router.use(async function (ctx, next) {
      const { user } = ctx.state;
      ctx.$pleasure.user = user;
      // console.log(`jwt check`, { user })

      // overhead
      /*
      if (user) {
        const { sessionId } = user

        if (await isJWTRevoked(sessionId) || !isValidSession(user)) {
          await logout(ctx)
        }
      }
*/

      return next()
    });

    router.post(revokeEndpoint, async (ctx, next) => {
      /*
      todo:
        - Validate session, then if valid
        - Blacklist session in db
        - Clean cookie
       */
      ctx.$pleasure.res = { ok: 'revoked!' };
      return next()
    });

    router.post(authEndpoint, async (ctx, next) => {
      const { entities } = await getEntities();
      const loginArguments = [ctx.request.body, qs.parse(ctx.request.querystring, { interpretNumericEntities: true }), ctx];

      if (typeof loginMethod === 'function') {
        ctx.$pleasure.res = await signIn$1(await loginMethod(...loginArguments));
      } else if (typeof loginMethod === 'string') {
        const entity = entities[authEntity];

        if (entity) {
          ctx.$pleasure.res = await signIn$1(await entity[loginMethod](...loginArguments));
          // todo: log operation
        } else {
          console.error(`authEntity ${ authEntity } not found`);
        }
      }

      return next()
      /*

          ctx.state.$pleasure

          const { api: { authentication, } } = getConfig()

          const { saltWorkFactor, jwtCookieName, sessionName, sessionLength, loginMethod } = authentication
          // todo: find modelAuthorizer
          const { user: userState } = ctx.state

          const user = ctx.request.body
          // const { captcha } = ctx.session

          if (!user || !user.email || !user.password) {
            throw new APIError('Enter username and password', 401)
          }

          if (user.mobile && (!/^(iOS|Android)$/.test(user.mobile.platform) || !user.mobile.uuid || !user.mobile.model || !user.mobile.serial)) {
            throw new APIError('errors.malformed')
          }

          const login = get(models, loginMethod)
          const error = `Wrong combination username / password`

          try {
            const foundUser = await login(user.email, user.password/!*, user.dfa*!/)

            /!*
             if the resulted access token exceed 4096 bytes
             the cookie would never be stored in the browser
             causing the user being prompted for login
             every time they refresh (SSR)

             solved by picking only certain important fields from the user
             ensuring the token won't exceed it's limit...
             or at least logging if so...
             *!/
            await sign(foundUser, { ctx, mobile: user.mobile })
          } catch (err) {
            console.log(err)
            /!*
                  appLogger.error(`login :: ${ user.email } :: ${ err.message }`)
                  pleasureError(ctx, error, 401)
            *!/
          }
      */
    });

    /*
        router.post('/logout', async function (ctx) {
          await logout(ctx)
          ctx.status = 200
        })
    */
  }
};

export default index;
