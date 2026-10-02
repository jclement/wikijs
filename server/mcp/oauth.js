const _ = require('lodash')
const crypto = require('crypto')

/* global WIKI */

// OAuth 2.1 authorization server for the MCP endpoint.
// Public clients only (PKCE S256 mandatory), opaque tokens stored hashed,
// rotating refresh tokens with reuse detection.

const SCOPES = {
  'wiki:read': 'Search and read the pages you can read',
  'wiki:write': 'Create, edit, move and delete pages you are allowed to change'
}
const DEFAULT_SCOPE = 'wiki:read'

const CODE_TTL = 5 * 60
const ACCESS_TTL = 60 * 60
const REFRESH_TTL = 30 * 24 * 60 * 60
const CONSENT_TTL = 10 * 60
const UNUSED_CLIENT_TTL = 24 * 60 * 60
const MAX_REDIRECT_URIS = 10

const FORBIDDEN_SCHEMES = ['javascript:', 'data:', 'file:', 'vbscript:', 'about:', 'blob:', 'ws:', 'wss:', 'ftp:']
const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]']

class OAuthError extends Error {
  constructor (code, description, status = 400) {
    super(description)
    this.code = code
    this.status = status
  }
}

const isoIn = seconds => new Date(Date.now() + seconds * 1000).toISOString()
const isoNow = () => new Date().toISOString()
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex')
const randomToken = prefix => `${prefix}${crypto.randomBytes(32).toString('base64url')}`

const parseUrl = value => {
  try {
    return new URL(value)
  } catch (err) {
    return null
  }
}

module.exports = {
  OAuthError,
  SCOPES,
  ACCESS_TTL,

  isEnabled () {
    return [true, 'true', 1, '1'].includes(_.get(WIKI.config, 'mcp.enabled', false))
  },

  /**
   * Public base URL of this wiki, without trailing slash
   */
  baseUrl () {
    return _.trimEnd(_.toString(WIKI.config.host), '/')
  },

  resourceUrl () {
    return `${this.baseUrl()}/mcp`
  },

  resourceMetadataUrl () {
    return `${this.baseUrl()}/.well-known/oauth-protected-resource/mcp`
  },

  /**
   * RFC 9728 - Protected Resource Metadata
   */
  getResourceMetadata () {
    return {
      resource: this.resourceUrl(),
      authorization_servers: [this.baseUrl()],
      scopes_supported: _.keys(SCOPES),
      bearer_methods_supported: ['header'],
      resource_name: WIKI.config.title
    }
  },

  /**
   * RFC 8414 - Authorization Server Metadata
   */
  getServerMetadata () {
    const base = this.baseUrl()
    return {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      revocation_endpoint: `${base}/oauth/revoke`,
      scopes_supported: _.keys(SCOPES),
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256']
    }
  },

  /**
   * Reduce a requested scope string to the scopes we know, always including read
   *
   * @param {String} scope Space separated scopes
   * @returns {Array<String>}
   */
  parseScope (scope) {
    const requested = _.isString(scope) && scope.trim().length > 0 ? scope.trim().split(/\s+/) : _.keys(SCOPES)
    return _.uniq([DEFAULT_SCOPE, ..._.intersection(requested, _.keys(SCOPES))])
  },

  /**
   * Only https, loopback http and private-use app schemes are allowed as redirect targets
   */
  isValidRedirectUri (uri) {
    if (!_.isString(uri) || uri.length > 2000) { return false }
    const url = parseUrl(uri)
    if (!url || url.hash || url.username || url.password) { return false }
    if (FORBIDDEN_SCHEMES.includes(url.protocol)) { return false }
    if (url.protocol === 'http:') {
      return LOOPBACK_HOSTS.includes(url.hostname)
    }
    return true
  },

  /**
   * Exact match, except that loopback redirects may use any port (RFC 8252 7.3)
   */
  matchRedirectUri (client, uri) {
    if (!_.isString(uri)) { return false }
    if (client.redirectUris.includes(uri)) { return true }
    const url = parseUrl(uri)
    if (!url || url.protocol !== 'http:' || !LOOPBACK_HOSTS.includes(url.hostname)) { return false }
    return client.redirectUris.some(registered => {
      const reg = parseUrl(registered)
      return reg && reg.protocol === 'http:' && reg.hostname === url.hostname &&
        reg.pathname === url.pathname && reg.search === url.search
    })
  },

  /**
   * RFC 7591 - Dynamic Client Registration (public clients only)
   */
  async registerClient (body) {
    if (!_.isPlainObject(body)) {
      throw new OAuthError('invalid_client_metadata', 'Request body must be a JSON object.')
    }
    const redirectUris = body.redirect_uris
    if (!_.isArray(redirectUris) || redirectUris.length < 1 || redirectUris.length > MAX_REDIRECT_URIS) {
      throw new OAuthError('invalid_redirect_uri', `redirect_uris must list between 1 and ${MAX_REDIRECT_URIS} URIs.`)
    }
    if (!redirectUris.every(uri => this.isValidRedirectUri(uri))) {
      throw new OAuthError('invalid_redirect_uri', 'Redirect URIs must use https, a loopback http address or an app-specific scheme, without fragment or credentials.')
    }
    const authMethod = body.token_endpoint_auth_method || 'none'
    if (authMethod !== 'none') {
      throw new OAuthError('invalid_client_metadata', 'Only public clients (token_endpoint_auth_method "none") are supported.')
    }
    if (_.isArray(body.grant_types) && !body.grant_types.includes('authorization_code')) {
      throw new OAuthError('invalid_client_metadata', 'The authorization_code grant type is required.')
    }
    if (_.isArray(body.response_types) && !body.response_types.includes('code')) {
      throw new OAuthError('invalid_client_metadata', 'The code response type is required.')
    }

    await this.prune()

    const client = {
      id: crypto.randomBytes(24).toString('base64url'),
      // Strip control characters: this name is shown to the user on the consent screen
      // eslint-disable-next-line no-control-regex
      name: _.truncate(_.toString(body.client_name || '').replace(/[\x00-\x1f\x7f]/g, '').trim() || 'Unnamed application', { length: 80 }),
      redirectUris: JSON.stringify(redirectUris),
      createdAt: isoNow()
    }
    await WIKI.models.knex('mcpClients').insert(client)

    return {
      client_id: client.id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: client.name,
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none'
    }
  },

  async getClient (id) {
    if (!_.isString(id) || id.length < 1 || id.length > 64) { return null }
    const client = await WIKI.models.knex('mcpClients').where('id', id).first()
    if (!client) { return null }
    return {
      ...client,
      redirectUris: JSON.parse(client.redirectUris)
    }
  },

  /**
   * Sign a value with the site secret (consent requests, CSRF tokens)
   */
  sign (value) {
    return crypto.createHmac('sha256', `mcp:${WIKI.config.sessionSecret}`).update(value).digest('base64url')
  },

  verifySignature (value, signature) {
    if (!_.isString(value) || !_.isString(signature)) { return false }
    const expected = Buffer.from(this.sign(value))
    const actual = Buffer.from(signature)
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual)
  },

  /**
   * Seal a validated authorization request, bound to the user it was shown to
   */
  sealConsent (request) {
    const payload = Buffer.from(JSON.stringify({
      ...request,
      exp: Date.now() + CONSENT_TTL * 1000
    })).toString('base64url')
    return { payload, signature: this.sign(payload) }
  },

  openConsent (payload, signature, userId) {
    if (!this.verifySignature(payload, signature)) { return null }
    try {
      const request = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
      if (request.exp < Date.now() || request.userId !== userId) { return null }
      return request
    } catch (err) {
      return null
    }
  },

  /**
   * Load a user that is allowed to use MCP, with fresh groups / permissions
   */
  async getUser (id) {
    if (!_.isInteger(id) || id === 2) { return null }
    const user = await WIKI.models.users.query().findById(id).withGraphFetched('groups').modifyGraph('groups', builder => {
      builder.select('groups.id', 'permissions')
    })
    const isTrue = v => v === true || v === 1
    if (!user || !isTrue(user.isActive) || !isTrue(user.isVerified)) { return null }
    user.permissions = user.getGlobalPermissions()
    return user
  },

  async insertToken ({ grantId, kind, ttl, meta }) {
    const prefix = { code: 'wmcp_ac_', access: 'wmcp_at_', refresh: 'wmcp_rt_' }[kind]
    const token = randomToken(prefix)
    await WIKI.models.knex('mcpTokens').insert({
      grantId,
      kind,
      hash: sha256(token),
      expiresAt: isoIn(ttl),
      meta: meta ? JSON.stringify(meta) : null
    })
    return token
  },

  /**
   * Record the user's approval and return a single-use authorization code
   */
  async createAuthorizationCode ({ clientId, userId, scopes, redirectUri, codeChallenge }) {
    const now = isoNow()
    const insert = WIKI.models.knex('mcpGrants').insert({
      clientId,
      userId,
      scope: scopes.join(' '),
      createdAt: now,
      lastUsedAt: now
    })
    // MySQL / MariaDB / SQLite return the new id without (and warn about) RETURNING
    const [inserted] = await (['postgres', 'mssql'].includes(_.get(WIKI.config, 'db.type')) ? insert.returning('id') : insert)
    const grantId = _.isObject(inserted) ? inserted.id : inserted
    return this.insertToken({
      grantId,
      kind: 'code',
      ttl: CODE_TTL,
      meta: { redirectUri, codeChallenge }
    })
  },

  /**
   * Atomically mark a single-use token as used. Returns false if it was already used.
   */
  async consumeToken (id) {
    const affected = await WIKI.models.knex('mcpTokens').where('id', id).whereNull('usedAt').update({ usedAt: isoNow() })
    return affected === 1
  },

  async findToken (token, kind) {
    if (!_.isString(token) || token.length > 200) { return null }
    return WIKI.models.knex('mcpTokens').where({ hash: sha256(token), kind }).first()
  },

  async issueTokens (grant) {
    await WIKI.models.knex('mcpTokens').where({ grantId: grant.id, kind: 'access' }).del()
    const accessToken = await this.insertToken({ grantId: grant.id, kind: 'access', ttl: ACCESS_TTL })
    const refreshToken = await this.insertToken({ grantId: grant.id, kind: 'refresh', ttl: REFRESH_TTL })
    await WIKI.models.knex('mcpGrants').where('id', grant.id).update({ lastUsedAt: isoNow() })
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL,
      refresh_token: refreshToken,
      scope: grant.scope
    }
  },

  /**
   * authorization_code grant
   */
  async exchangeCode ({ code, clientId, redirectUri, codeVerifier }) {
    const entry = await this.findToken(code, 'code')
    if (!entry) {
      throw new OAuthError('invalid_grant', 'Authorization code is invalid.')
    }
    const grant = await WIKI.models.knex('mcpGrants').where('id', entry.grantId).first()
    if (!grant || grant.clientId !== clientId) {
      throw new OAuthError('invalid_grant', 'Authorization code is invalid.')
    }
    if (!(await this.consumeToken(entry.id))) {
      // A code presented twice means it leaked: drop everything issued from it
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'Authorization code was already used.')
    }
    if (entry.expiresAt < isoNow()) {
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'Authorization code has expired.')
    }
    const meta = JSON.parse(entry.meta)
    if (meta.redirectUri !== redirectUri) {
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request.')
    }
    if (!_.isString(codeVerifier) || !/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) {
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'code_verifier is missing or malformed.')
    }
    const challenge = Buffer.from(crypto.createHash('sha256').update(codeVerifier).digest('base64url'))
    const expected = Buffer.from(meta.codeChallenge)
    if (challenge.length !== expected.length || !crypto.timingSafeEqual(challenge, expected)) {
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'PKCE verification failed.')
    }
    if (!(await this.getUser(grant.userId))) {
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'User account is not available.')
    }
    await WIKI.models.knex('mcpTokens').where('id', entry.id).del()
    return this.issueTokens(grant)
  },

  /**
   * refresh_token grant, rotating the refresh token on every use
   */
  async refresh ({ refreshToken, clientId }) {
    const entry = await this.findToken(refreshToken, 'refresh')
    if (!entry) {
      throw new OAuthError('invalid_grant', 'Refresh token is invalid.')
    }
    const grant = await WIKI.models.knex('mcpGrants').where('id', entry.grantId).first()
    if (!grant || grant.clientId !== clientId) {
      throw new OAuthError('invalid_grant', 'Refresh token is invalid.')
    }
    if (!(await this.consumeToken(entry.id))) {
      // Reuse of a rotated refresh token: assume theft and end the connection
      WIKI.logger.warn(`MCP: refresh token reuse detected for user ${grant.userId}, revoking grant ${grant.id}.`)
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'Refresh token was already used.')
    }
    if (entry.expiresAt < isoNow()) {
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'Refresh token has expired.')
    }
    if (!(await this.getUser(grant.userId))) {
      await this.deleteGrant(grant.id)
      throw new OAuthError('invalid_grant', 'User account is not available.')
    }
    return this.issueTokens(grant)
  },

  /**
   * Resolve an access token to its user and scopes, or null
   */
  async authenticate (accessToken) {
    const entry = await this.findToken(accessToken, 'access')
    if (!entry || entry.expiresAt < isoNow()) { return null }
    const grant = await WIKI.models.knex('mcpGrants').where('id', entry.grantId).first()
    if (!grant) { return null }
    const user = await this.getUser(grant.userId)
    if (!user) { return null }
    const client = await WIKI.models.knex('mcpClients').where('id', grant.clientId).first()
    if (grant.lastUsedAt < isoIn(-300)) {
      await WIKI.models.knex('mcpGrants').where('id', grant.id).update({ lastUsedAt: isoNow() })
    }
    return {
      user,
      scopes: grant.scope.split(' '),
      grantId: grant.id,
      clientName: _.get(client, 'name', 'Unknown')
    }
  },

  /**
   * RFC 7009 - revoking either token ends the whole connection
   */
  async revokeToken (token) {
    const entry = await this.findToken(token, 'refresh') || await this.findToken(token, 'access')
    if (entry) {
      await this.deleteGrant(entry.grantId)
    }
  },

  // Deletes are explicit rather than relying on ON DELETE CASCADE, which SQLite does not enforce here
  async deleteGrant (id) {
    await WIKI.models.knex('mcpTokens').where('grantId', id).del()
    await WIKI.models.knex('mcpGrants').where('id', id).del()
  },

  async listGrants (userId) {
    const now = isoNow()
    const grants = await WIKI.models.knex('mcpGrants')
      .join('mcpClients', 'mcpGrants.clientId', 'mcpClients.id')
      .where('mcpGrants.userId', userId)
      .whereIn('mcpGrants.id', function () {
        this.select('grantId').from('mcpTokens').where('kind', 'refresh').whereNull('usedAt').where('expiresAt', '>', now)
      })
      .select('mcpGrants.id', 'mcpGrants.scope', 'mcpGrants.createdAt', 'mcpGrants.lastUsedAt', { clientName: 'mcpClients.name' })
      .orderBy('mcpGrants.lastUsedAt', 'desc')
    return grants
  },

  async revokeGrant (id, userId) {
    const grant = await WIKI.models.knex('mcpGrants').where({ id, userId }).first()
    if (!grant) { return false }
    await this.deleteGrant(grant.id)
    return true
  },

  /**
   * Remove expired tokens, grants with no tokens left and clients that never completed a connection
   */
  async prune () {
    const knex = WIKI.models.knex
    await knex('mcpTokens').where('expiresAt', '<', isoNow()).del()
    await knex('mcpGrants').whereNotIn('id', function () {
      this.select('grantId').from('mcpTokens')
    }).del()
    await knex('mcpClients').where('createdAt', '<', isoIn(-UNUSED_CLIENT_TTL)).whereNotIn('id', function () {
      this.select('clientId').from('mcpGrants')
    }).del()
  }
}
