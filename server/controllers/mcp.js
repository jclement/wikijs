const express = require('express')
const router = express.Router()
const _ = require('lodash')
const fs = require('fs-extra')
const assets = require('../mcp/assets')
const oauth = require('../mcp/oauth')
const rpc = require('../mcp/rpc')

/* global WIKI */

const { OAuthError } = oauth

// ----------------------------------------
// Helpers
// ----------------------------------------

const param = value => (_.isString(value) && value.length > 0) ? value : undefined

const secureHeaders = res => {
  res.set('Cache-Control', 'no-store')
  res.set('Pragma', 'no-cache')
}

// Consent and connection pages are self-contained: no scripts, never framed
const pageHeaders = res => {
  secureHeaders(res)
  res.set('X-Frame-Options', 'deny')
  res.set('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'`)
  res.set('Referrer-Policy', 'no-referrer')
}

const renderMessage = (res, status, title, message) => {
  pageHeaders(res)
  res.status(status).render('mcp/message', { title, message })
}

const sendOAuthError = (res, err) => {
  secureHeaders(res)
  if (err instanceof OAuthError) {
    return res.status(err.status).json({ error: err.code, error_description: err.message })
  }
  WIKI.logger.warn(`MCP: OAuth request failed: ${err.message}`)
  res.status(500).json({ error: 'server_error', error_description: 'Internal error.' })
}

const redirectWith = (res, redirectUri, params) => {
  const url = new URL(redirectUri)
  _.forOwn(params, (value, key) => {
    if (!_.isUndefined(value)) { url.searchParams.set(key, value) }
  })
  url.searchParams.set('iss', oauth.baseUrl())
  secureHeaders(res)
  res.redirect(url.toString())
}

/**
 * Stream a request body to a file, failing once it grows past maxBytes
 */
const receiveBody = (req, dest, maxBytes) => new Promise((resolve, reject) => {
  const out = fs.createWriteStream(dest)
  let size = 0
  let settled = false
  const fail = err => {
    if (settled) { return }
    settled = true
    req.unpipe(out)
    out.destroy()
    reject(err)
  }
  req.on('data', chunk => {
    size += chunk.length
    if (size > maxBytes) {
      fail(new assets.AssetError(`The file is larger than the ${maxBytes} byte limit of this wiki.`, 413))
    }
  })
  req.on('aborted', () => fail(new Error('upload aborted by the client')))
  req.on('error', fail)
  out.on('error', fail)
  out.on('finish', () => {
    if (!settled) {
      settled = true
      resolve(size)
    }
  })
  req.pipe(out)
})

const sendFileError = (res, status, message) => {
  secureHeaders(res)
  if (status === 413) { res.set('Connection', 'close') }
  res.status(status).json({ ok: false, error: message })
}

const isSignedIn = req => req.user && _.isInteger(req.user.id) && req.user.id !== 2

/**
 * Fixed-window rate limit per client IP, in memory
 */
const buckets = new Map()
const rateLimit = (name, max, windowMs) => (req, res, next) => {
  const now = Date.now()
  if (buckets.size > 10000) {
    buckets.forEach((bucket, key) => {
      if (bucket.reset < now) { buckets.delete(key) }
    })
  }
  const key = `${name}:${req.ip}`
  let bucket = buckets.get(key)
  if (!bucket || bucket.reset < now) {
    bucket = { count: 0, reset: now + windowMs }
    buckets.set(key, bucket)
  }
  bucket.count++
  if (bucket.count > max) {
    res.set('Retry-After', _.toString(Math.ceil((bucket.reset - now) / 1000)))
    return res.status(429).json({ error: 'temporarily_unavailable', error_description: 'Too many requests. Try again later.' })
  }
  next()
}

// ----------------------------------------
// Everything below only exists when MCP is enabled and the site URL is known
// ----------------------------------------

router.use((req, res, next) => {
  if (oauth.isEnabled() && oauth.baseUrl().length > 0) {
    next()
  } else {
    next('router')
  }
})

/**
 * Discovery
 */
router.get(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], (req, res) => {
  res.json(oauth.getResourceMetadata())
})
router.get(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp'], (req, res) => {
  res.json({
    ...oauth.getServerMetadata(),
    authorization_response_iss_parameter_supported: true
  })
})

/**
 * Dynamic Client Registration
 */
router.post('/oauth/register', rateLimit('register', 30, 60 * 60 * 1000), async (req, res) => {
  try {
    const client = await oauth.registerClient(req.body)
    secureHeaders(res)
    res.status(201).json(client)
  } catch (err) {
    sendOAuthError(res, err)
  }
})

/**
 * Authorization - consent screen
 */
router.get('/oauth/authorize', async (req, res, next) => {
  try {
    const query = _.mapValues(req.query, param)

    // Until the client and its redirect URI are verified, errors must not be redirected anywhere
    const client = await oauth.getClient(query.client_id)
    if (!client) {
      return renderMessage(res, 400, 'Unknown application', 'This application is not registered with this wiki. Try connecting again from the application.')
    }
    if (!oauth.matchRedirectUri(client, query.redirect_uri)) {
      return renderMessage(res, 400, 'Invalid request', 'The return address in this request does not match the one the application registered.')
    }

    const fail = (error, description) => redirectWith(res, query.redirect_uri, { error, error_description: description, state: query.state })
    if (query.response_type !== 'code') {
      return fail('unsupported_response_type', 'Only the code response type is supported.')
    }
    if (query.code_challenge_method !== 'S256' || !/^[A-Za-z0-9\-_]{43}$/.test(query.code_challenge || '')) {
      return fail('invalid_request', 'PKCE with the S256 challenge method is required.')
    }
    if (query.resource && _.trimEnd(query.resource, '/') !== oauth.resourceUrl()) {
      return fail('invalid_target', 'Unknown resource.')
    }
    if (query.state && query.state.length > 1000) {
      return fail('invalid_request', 'state is too long.')
    }

    // Send guests through the normal login (incl. 2FA / SSO), then back here
    if (!isSignedIn(req)) {
      const search = new URLSearchParams(_.omitBy(query, _.isUndefined)).toString()
      res.cookie('loginRedirect', `/oauth/authorize?${search}`, { maxAge: 15 * 60 * 1000 })
      secureHeaders(res)
      return res.redirect('/login')
    }
    const user = await oauth.getUser(req.user.id)
    if (!user) {
      return renderMessage(res, 403, 'Account unavailable', 'Your account cannot be used to connect applications.')
    }

    const scopes = oauth.parseScope(query.scope)
    const sealed = oauth.sealConsent({
      userId: user.id,
      clientId: client.id,
      redirectUri: query.redirect_uri,
      codeChallenge: query.code_challenge,
      scopes,
      state: query.state
    })
    const redirectUrl = new URL(query.redirect_uri)

    pageHeaders(res)
    res.render('mcp/consent', {
      title: 'Connect application',
      clientName: client.name,
      redirectTarget: redirectUrl.host ? `${redirectUrl.protocol}//${redirectUrl.host}` : `${redirectUrl.protocol} (an application on your device)`,
      siteTitle: WIKI.config.title,
      user,
      canRequestWrite: scopes.includes('wiki:write'),
      scopeLabels: oauth.SCOPES,
      sealed
    })
  } catch (err) {
    next(err)
  }
})

/**
 * Authorization - decision
 */
router.post('/oauth/authorize', async (req, res, next) => {
  try {
    const body = req.body || {}
    // The sealed request is signed and bound to the user it was rendered for, which also makes it the CSRF token
    const request = isSignedIn(req) ? oauth.openConsent(body.request, body.signature, req.user.id) : null
    if (!request) {
      return renderMessage(res, 400, 'Request expired', 'This authorization request is no longer valid. Start the connection again from the application.')
    }
    const client = await oauth.getClient(request.clientId)
    const user = await oauth.getUser(request.userId)
    if (!client || !user || !oauth.matchRedirectUri(client, request.redirectUri)) {
      return renderMessage(res, 400, 'Request expired', 'This authorization request is no longer valid. Start the connection again from the application.')
    }

    if (body.decision !== 'approve') {
      return redirectWith(res, request.redirectUri, { error: 'access_denied', error_description: 'The user denied the request.', state: request.state })
    }

    const scopes = request.scopes.filter(scope => scope !== 'wiki:write' || body.allow_write === '1')
    const code = await oauth.createAuthorizationCode({
      clientId: client.id,
      userId: user.id,
      scopes,
      redirectUri: request.redirectUri,
      codeChallenge: request.codeChallenge
    })
    WIKI.logger.info(`MCP: user ${user.id} connected "${client.name}" with scopes ${scopes.join(' ')}`)
    redirectWith(res, request.redirectUri, { code, state: request.state })
  } catch (err) {
    next(err)
  }
})

/**
 * Token endpoint
 */
router.post('/oauth/token', rateLimit('token', 300, 10 * 60 * 1000), async (req, res) => {
  try {
    const body = _.mapValues(req.body || {}, param)
    const client = await oauth.getClient(body.client_id)
    if (!client) {
      throw new OAuthError('invalid_client', 'Unknown client.', 401)
    }
    let tokens
    switch (body.grant_type) {
      case 'authorization_code':
        tokens = await oauth.exchangeCode({
          code: body.code,
          clientId: client.id,
          redirectUri: body.redirect_uri,
          codeVerifier: body.code_verifier
        })
        break
      case 'refresh_token':
        tokens = await oauth.refresh({
          refreshToken: body.refresh_token,
          clientId: client.id
        })
        break
      default:
        throw new OAuthError('unsupported_grant_type', 'Supported grant types: authorization_code, refresh_token.')
    }
    secureHeaders(res)
    res.json(tokens)
  } catch (err) {
    sendOAuthError(res, err)
  }
})

/**
 * Token revocation
 */
router.post('/oauth/revoke', rateLimit('token', 300, 10 * 60 * 1000), async (req, res) => {
  try {
    await oauth.revokeToken(param(_.get(req.body, 'token')))
    secureHeaders(res)
    res.status(200).json({})
  } catch (err) {
    sendOAuthError(res, err)
  }
})

/**
 * Connected applications - lets users review and revoke access
 */
router.get('/oauth/connections', async (req, res, next) => {
  try {
    if (!isSignedIn(req)) {
      res.cookie('loginRedirect', '/oauth/connections', { maxAge: 15 * 60 * 1000 })
      return res.redirect('/login')
    }
    const grants = await oauth.listGrants(req.user.id)
    pageHeaders(res)
    res.render('mcp/connections', {
      title: 'Connected applications',
      siteTitle: WIKI.config.title,
      mcpUrl: oauth.resourceUrl(),
      revoked: req.query.revoked === '1',
      grants: grants.map(grant => ({
        ...grant,
        readOnly: !grant.scope.split(' ').includes('wiki:write'),
        csrf: oauth.sign(`revoke:${req.user.id}:${grant.id}`)
      }))
    })
  } catch (err) {
    next(err)
  }
})

router.post('/oauth/connections/revoke', async (req, res, next) => {
  try {
    const grantId = _.toSafeInteger(_.get(req.body, 'grant'))
    if (!isSignedIn(req) || !oauth.verifySignature(`revoke:${req.user.id}:${grantId}`, _.get(req.body, 'csrf'))) {
      return renderMessage(res, 400, 'Request expired', 'This request is no longer valid. Go back and try again.')
    }
    if (await oauth.revokeGrant(grantId, req.user.id)) {
      WIKI.logger.info(`MCP: user ${req.user.id} revoked connection ${grantId}`)
    }
    res.redirect('/oauth/connections?revoked=1')
  } catch (err) {
    next(err)
  }
})

/**
 * File links handed out by the asset tools. The token in the URL is the only credential:
 * it is bound to one file and one connection, and the user's permissions are checked again on use.
 */
const fileRateLimit = rateLimit('files', 300, 10 * 60 * 1000)

router.get('/mcp/download/:token', fileRateLimit, async (req, res) => {
  try {
    const file = await oauth.openFileToken(req.params.token, 'download')
    const asset = file ? await assets.findReadable(file.user, file.assetPath) : null
    if (!asset) {
      return sendFileError(res, 404, 'This download link is invalid or has expired.')
    }
    const data = await assets.readData(asset)
    secureHeaders(res)
    res.attachment(asset.filename)
    res.set('Content-Type', assets.mimeOf(asset.filename))
    res.set('X-Content-Type-Options', 'nosniff')
    res.set('Content-Security-Policy', `default-src 'none'; sandbox`)
    res.set('Referrer-Policy', 'no-referrer')
    res.send(data)
  } catch (err) {
    if (err instanceof assets.AssetError) {
      return sendFileError(res, 404, 'This download link is invalid or has expired.')
    }
    WIKI.logger.warn(`MCP: file download failed: ${err.message}`)
    sendFileError(res, 500, 'Internal error.')
  }
})

const receiveUpload = async (req, res) => {
  // Bodies of these types were already consumed by the wiki's body parsers: refuse before using up the link
  if (req.is('json') || req.is('urlencoded') || req.is('multipart')) {
    return sendFileError(res, 415, 'Send the raw file bytes as the request body (e.g. curl -T file "<url>"), not JSON, a form or multipart/form-data. This link has not been used up.')
  }
  if (_.toSafeInteger(req.get('content-length')) > assets.maxFileSize()) {
    return sendFileError(res, 413, `The file is larger than the ${assets.maxFileSize()} byte limit of this wiki.`)
  }
  let tmpPath = null
  try {
    const file = await oauth.openFileToken(req.params.token, 'upload')
    if (!file) {
      return sendFileError(res, 404, 'This upload link is invalid, has expired or was already used. Ask for a new one with create_asset_upload.')
    }
    tmpPath = await assets.tempPath()
    await receiveBody(req, tmpPath, assets.maxFileSize())
    const stored = await assets.store(file.user, file.assetPath, tmpPath, { overwrite: file.overwrite })
    WIKI.logger.info(`MCP: user ${file.user.id} via "${file.clientName}" ${stored.replaced ? 'replaced file' : 'uploaded file'} ${stored.path} (${stored.size} bytes)`)
    secureHeaders(res)
    res.status(201).json({
      ok: true,
      path: stored.path,
      url: `${oauth.baseUrl()}/${stored.path}`,
      size: stored.size,
      replaced: stored.replaced,
      markdown: assets.markdownFor(stored.path)
    })
  } catch (err) {
    if (tmpPath) { await fs.remove(tmpPath).catch(() => {}) }
    if (err instanceof assets.AssetError) {
      return sendFileError(res, err.status, `${err.message} This link has been used up; ask for a new one with create_asset_upload.`)
    }
    WIKI.logger.warn(`MCP: file upload failed: ${err.message}`)
    if (!res.headersSent && !req.aborted) {
      sendFileError(res, 500, 'The wiki could not store the file because of an internal error.')
    }
  }
}

router.put('/mcp/upload/:token', fileRateLimit, receiveUpload)
router.post('/mcp/upload/:token', fileRateLimit, receiveUpload)
router.all(['/mcp/upload/:token', '/mcp/download/:token'], (req, res) => {
  res.set('Allow', req.path.startsWith('/mcp/upload/') ? 'PUT, POST' : 'GET')
  sendFileError(res, 405, 'Method not allowed.')
})

/**
 * MCP endpoint (Streamable HTTP, stateless)
 */
router.all('/mcp', async (req, res) => {
  secureHeaders(res)
  if (req.method !== 'POST') {
    res.set('Allow', 'POST')
    return res.status(405).json(rpc.rpcError(null, -32000, 'Method not allowed. This server only accepts POST.'))
  }
  try {
    // Only bearer tokens issued by this server are accepted here: never the browser session
    const bearer = /^Bearer\s+(\S+)$/i.exec(req.get('authorization') || '')
    const ctx = bearer ? await oauth.authenticate(bearer[1]) : null
    if (!ctx) {
      res.set('WWW-Authenticate', `Bearer resource_metadata="${oauth.resourceMetadataUrl()}"${bearer ? ', error="invalid_token"' : ''}`)
      return res.status(401).json(rpc.rpcError(null, -32001, 'Authentication required.'))
    }
    const version = req.get('mcp-protocol-version')
    if (version && !rpc.PROTOCOL_VERSIONS.includes(version)) {
      return res.status(400).json(rpc.rpcError(null, -32000, `Unsupported MCP-Protocol-Version: ${version}`))
    }
    const response = await rpc.handle(req.body, ctx)
    if (!response) {
      return res.status(202).end()
    }
    res.json(response)
  } catch (err) {
    WIKI.logger.warn(`MCP: request failed: ${err.message}`)
    res.status(500).json(rpc.rpcError(_.get(req.body, 'id', null), -32603, 'Internal error.'))
  }
})

/**
 * Errors raised before the routes above are reached (e.g. malformed request bodies)
 * must still be answered in the format API clients expect
 */
router.errorHandler = (err, req, res, next) => {
  const isUpload = req.path.startsWith('/mcp/upload/')
  const isApiPath = req.path === '/mcp' || isUpload || (req.method === 'POST' && ['/oauth/register', '/oauth/token', '/oauth/revoke'].includes(req.path))
  if (!isApiPath || !oauth.isEnabled()) {
    return next(err)
  }
  const status = (err.status >= 400 && err.status < 500) ? err.status : 500
  secureHeaders(res)
  if (isUpload) {
    if (status === 500) {
      sendFileError(res, 500, 'Internal error.')
    } else {
      sendFileError(res, 415, 'Send the raw file bytes as the request body (e.g. curl -T file "<url>"), not JSON or a form. This link has not been used up.')
    }
  } else if (req.path === '/mcp') {
    res.status(status).json(status === 500 ? rpc.rpcError(null, -32603, 'Internal error.') : rpc.rpcError(null, -32700, 'Parse error: request body is not valid JSON.'))
  } else {
    res.status(status).json(status === 500 ? { error: 'server_error' } : { error: 'invalid_request', error_description: 'Malformed request body.' })
  }
}

router.rateLimitBuckets = buckets

module.exports = router
