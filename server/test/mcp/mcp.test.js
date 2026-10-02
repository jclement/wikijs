/**
 * @jest-environment node
 */

const crypto = require('crypto')
const fs = require('fs-extra')
const http = require('http')
const os = require('os')
const path = require('path')
const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const Knex = require('knex')

/* global WIKI */

// core/auth is loaded for its real checkAccess logic only; token signing is not exercised here
jest.mock('jsonwebtoken', () => ({}))
jest.mock('passport-jwt', () => ({
  ExtractJwt: { fromExtractors: () => () => null, fromAuthHeaderAsBearerToken: () => () => null }
}))

const HOST = 'https://wiki.test'
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback'

// ----------------------------------------
// Fixtures
// ----------------------------------------

const users = {
  // Administrator
  1: { id: 1, name: 'Admin', email: 'admin@wiki.test', isActive: true, isVerified: true, groups: [{ id: 1, permissions: ['manage:system'] }] },
  // Regular editor, limited to the "team" folder by page rules
  3: { id: 3, name: 'Erin Editor', email: 'erin@wiki.test', isActive: true, isVerified: true, groups: [{ id: 3, permissions: ['read:pages', 'read:source', 'write:pages', 'read:assets', 'write:assets'] }] },
  // Reader of everything
  4: { id: 4, name: 'Rae Reader', email: 'rae@wiki.test', isActive: true, isVerified: true, groups: [{ id: 4, permissions: ['read:pages'] }] }
}

const groups = {
  1: { id: 1, permissions: ['manage:system'], pageRules: [] },
  3: {
    id: 3,
    permissions: ['read:pages', 'read:source', 'write:pages', 'read:assets', 'write:assets'],
    pageRules: [
      { id: 'a', deny: false, match: 'START', roles: ['read:pages', 'read:source', 'write:pages', 'read:assets', 'write:assets'], path: 'team', locales: [] },
      { id: 'c', deny: true, match: 'EXACT', roles: ['read:assets'], path: 'team/private.png', locales: [] },
      { id: 'd', deny: true, match: 'EXACT', roles: ['read:assets'], path: 'team/english.png', locales: ['en'] }
    ]
  },
  4: {
    id: 4,
    permissions: ['read:pages'],
    pageRules: [{ id: 'b', deny: false, match: 'START', roles: ['read:pages'], path: '', locales: [] }]
  }
}

const makePage = (id, pagePath, content, extra = {}) => ({
  id,
  path: pagePath,
  localeCode: 'en',
  title: `Title ${id}`,
  description: '',
  content,
  render: `<p>${content}</p>`,
  contentType: 'markdown',
  isPublished: true,
  publishStartDate: '',
  publishEndDate: '',
  tags: [],
  extra: { js: 'alert(1)', css: 'body{}' },
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-02T00:00:00.000Z',
  authorName: 'Admin',
  creatorName: 'Admin',
  ...extra
})

let pages

const userQuery = id => {
  const user = users[id] ? {
    ...users[id],
    getGlobalPermissions () { return [].concat(...this.groups.map(g => g.permissions)) }
  } : undefined
  const chain = {
    withGraphFetched: () => chain,
    modifyGraph: () => chain,
    then: (resolve, reject) => Promise.resolve(user).then(resolve, reject)
  }
  return chain
}

// ----------------------------------------
// HTTP helpers
// ----------------------------------------

let server
let knex

const request = (method, urlPath, { headers = {}, json, form, raw } = {}) => new Promise((resolve, reject) => {
  let payload = null
  if (json !== undefined) {
    payload = JSON.stringify(json)
    headers['content-type'] = 'application/json'
  } else if (form) {
    payload = new URLSearchParams(form).toString()
    headers['content-type'] = 'application/x-www-form-urlencoded'
  } else if (raw) {
    payload = raw
  }
  const req = http.request({ host: '127.0.0.1', port: server.address().port, path: urlPath, method, headers }, res => {
    const chunks = []
    res.on('data', chunk => { chunks.push(chunk) })
    res.on('end', () => {
      const data = Buffer.concat(chunks)
      const text = data.toString('utf8')
      let body = null
      try { body = JSON.parse(text) } catch (err) {}
      resolve({ status: res.statusCode, headers: res.headers, text, body, data })
    })
  })
  req.on('error', reject)
  if (payload) { req.write(payload) }
  req.end()
})

const as = userId => ({ 'x-test-user': String(userId) })

const pkce = () => {
  const verifier = crypto.randomBytes(32).toString('base64url')
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }
}

const register = async (overrides = {}) => {
  const res = await request('POST', '/oauth/register', { json: { client_name: 'Claude', redirect_uris: [REDIRECT], ...overrides } })
  return res
}

const authorizeUrl = (clientId, challenge, extra = {}) => '/oauth/authorize?' + new URLSearchParams({
  response_type: 'code',
  client_id: clientId,
  redirect_uri: REDIRECT,
  code_challenge: challenge,
  code_challenge_method: 'S256',
  state: 'xyz',
  ...extra
}).toString()

const hidden = (html, name) => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)[1]

/**
 * Run the whole authorization flow and return the token response
 */
const connect = async (userId, { allowWrite = true, scope } = {}) => {
  const client = (await register()).body
  const { verifier, challenge } = pkce()
  const consent = await request('GET', authorizeUrl(client.client_id, challenge, scope ? { scope } : {}), { headers: as(userId) })
  const decision = await request('POST', '/oauth/authorize', {
    headers: as(userId),
    form: {
      request: hidden(consent.text, 'request'),
      signature: hidden(consent.text, 'signature'),
      decision: 'approve',
      ...(allowWrite ? { allow_write: '1' } : {})
    }
  })
  const code = new URL(decision.headers.location).searchParams.get('code')
  const tokens = await request('POST', '/oauth/token', {
    form: { grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: REDIRECT, code_verifier: verifier }
  })
  return { client, code, verifier, tokens: tokens.body, status: tokens.status }
}

let rpcId = 0
const rpc = (token, method, params) => request('POST', '/mcp', {
  headers: { authorization: `Bearer ${token}` },
  json: { jsonrpc: '2.0', id: ++rpcId, method, params }
})
const callTool = async (token, name, args) => (await rpc(token, 'tools/call', { name, arguments: args })).body.result

// The path part of a file link returned by a tool
const linkIn = (result, kind) => {
  const match = new RegExp(`${HOST}(/mcp/${kind}/[A-Za-z0-9_-]+)`).exec(result.content[0].text)
  return match ? match[1] : null
}

const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64')

let dataRoot

const folderOf = async (parentId, slug) => {
  const query = knex('assetFolders').where('slug', slug)
  return (parentId ? query.where('parentId', parentId) : query.whereNull('parentId')).first()
}

const seedAsset = async (folderSlug, filename, data) => {
  let folder = await folderOf(null, folderSlug)
  if (!folder) {
    await knex('assetFolders').insert({ slug: folderSlug, name: folderSlug, parentId: null })
    folder = await folderOf(null, folderSlug)
  }
  const [id] = await knex('assets').insert({ filename, ext: path.extname(filename), kind: 'image', mime: 'image/png', fileSize: data.length, folderId: folder.id, authorId: 1, createdAt: '2026-01-01', updatedAt: '2026-01-01' })
  await knex('assetData').insert({ id, data })
}

const storedAsset = async assetPath => {
  const parts = assetPath.split('/')
  const filename = parts.pop()
  let folderId = null
  for (const slug of parts) {
    const folder = await folderOf(folderId, slug)
    if (!folder) { return null }
    folderId = folder.id
  }
  const query = knex('assets').where('filename', filename)
  const asset = await (folderId ? query.where('folderId', folderId) : query.whereNull('folderId')).first()
  if (!asset) { return null }
  return { ...asset, data: (await knex('assetData').where('id', asset.id).first()).data }
}

// ----------------------------------------
// Setup
// ----------------------------------------

beforeAll(async () => {
  knex = Knex({ client: 'sqlite3', connection: { filename: ':memory:' }, useNullAsDefault: true })
  await knex.schema.createTable('users', table => { table.increments('id').primary() })
  await require('../../db/migrations-sqlite/2.5.129').up(knex)
  await knex.schema.createTable('assetFolders', table => {
    table.increments('id').primary()
    table.string('name')
    // Case-insensitive, like MySQL / MSSQL default collations
    table.specificType('slug', 'varchar(255) collate nocase')
    table.integer('parentId')
  })
  await knex.schema.createTable('assets', table => {
    table.increments('id').primary()
    table.specificType('filename', 'varchar(255) collate nocase')
    table.string('ext')
    table.string('kind')
    table.string('mime')
    table.integer('fileSize')
    table.integer('folderId')
    table.integer('authorId')
    table.string('createdAt')
    table.string('updatedAt')
  })
  await knex.schema.createTable('assetData', table => {
    table.integer('id').primary()
    table.binary('data')
  })
  dataRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'wiki-mcp-test-'))

  global.WIKI = {
    version: '2.5.0',
    ROOTPATH: dataRoot,
    config: {
      host: HOST,
      title: 'Test Wiki',
      sessionSecret: 'test-secret',
      mcp: { enabled: true },
      lang: { code: 'en', namespaces: [] },
      dataPath: './data',
      uploads: { maxFileSize: 2000 },
      pageExtensions: ['md', 'html', 'txt']
    },
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
    data: {
      reservedPaths: ['login', 'img', 'js'],
      searchEngine: {
        query: async () => ({ results: pages.map(p => ({ id: p.id, path: p.path, locale: 'en', title: p.title, description: '' })), suggestions: [], totalHits: pages.length })
      }
    },
    models: {
      knex,
      users: { query: () => ({ findById: userQuery }) },
      pages: {
        getPageFromDb: jest.fn(async ({ path: pagePath, locale }) => pages.find(p => p.path === pagePath && p.localeCode === locale)),
        updatePage: jest.fn(async opts => ({ ...pages.find(p => p.id === opts.id), content: opts.content, updatedAt: '2026-02-01T00:00:00.000Z' })),
        createPage: jest.fn(),
        deletePage: jest.fn(),
        movePage: jest.fn()
      },
      assets: {
        // Stand-in for the asset model: stores the file and removes the temporary upload
        upload: jest.fn(async opts => {
          const data = await fs.readFile(opts.path)
          const query = knex('assets').where('filename', opts.originalname)
          const existing = await (opts.folderId ? query.where('folderId', opts.folderId) : query.whereNull('folderId')).first()
          if (existing) {
            await knex('assets').where('id', existing.id).update({ fileSize: opts.size, mime: opts.mimetype })
            await knex('assetData').where('id', existing.id).update({ data })
          } else {
            const [id] = await knex('assets').insert({ filename: opts.originalname, ext: path.extname(opts.originalname), kind: 'binary', mime: opts.mimetype, fileSize: opts.size, folderId: opts.folderId, authorId: opts.user.id, createdAt: 'now', updatedAt: 'now' })
            await knex('assetData').insert({ id, data })
          }
          await fs.remove(opts.path)
        })
      }
    }
  }
  WIKI.auth = require('../../core/auth')
  WIKI.auth.groups = groups

  const app = express()
  app.use(cookieParser())
  app.use(bodyParser.json())
  app.use(bodyParser.urlencoded({ extended: false }))
  app.set('views', path.join(__dirname, '../../views'))
  app.set('view engine', 'pug')
  app.locals.config = WIKI.config
  // Stand-in for the wiki session: guest unless the test says otherwise
  app.use((req, res, next) => {
    const id = parseInt(req.get('x-test-user') || '2', 10)
    req.user = { id }
    next()
  })
  app.use('/', require('../../controllers/mcp'))
  app.use((req, res) => res.status(404).send('wiki fallthrough'))
  await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve) })
})

afterAll(async () => {
  await new Promise(resolve => server.close(resolve))
  await knex.destroy()
  await fs.remove(dataRoot)
})

beforeEach(() => {
  pages = [
    makePage(10, 'team/notes', 'alpha beta alpha'),
    makePage(11, 'hr/salaries', 'secret numbers'),
    makePage(12, 'team/draft', 'work in progress', { isPublished: false })
  ]
  WIKI.config.mcp.enabled = true
  users[3].isActive = true
  require('../../controllers/mcp').rateLimitBuckets.clear()
  jest.clearAllMocks()
})

beforeEach(async () => {
  await knex('assetData').del()
  await knex('assets').del()
  await knex('assetFolders').del()
  await seedAsset('team', 'logo.png', PNG)
  await seedAsset('team', 'notes.svg', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'))
  await seedAsset('hr', 'secret.png', PNG)
  await seedAsset('team', 'private.png', PNG)
  await seedAsset('team', 'english.png', PNG)
})

// ----------------------------------------
// Tests
// ----------------------------------------

describe('mcp/discovery', () => {
  it('publishes protected resource and authorization server metadata', async () => {
    const resource = await request('GET', '/.well-known/oauth-protected-resource/mcp')
    expect(resource.body.resource).toBe(`${HOST}/mcp`)
    expect(resource.body.authorization_servers).toEqual([HOST])

    const meta = await request('GET', '/.well-known/oauth-authorization-server')
    expect(meta.body.issuer).toBe(HOST)
    expect(meta.body.code_challenge_methods_supported).toEqual(['S256'])
    expect(meta.body.token_endpoint_auth_methods_supported).toEqual(['none'])
  })

  it('does not exist at all when disabled', async () => {
    WIKI.config.mcp.enabled = false
    for (const [method, url] of [['GET', '/.well-known/oauth-authorization-server'], ['POST', '/mcp'], ['POST', '/oauth/register']]) {
      const res = await request(method, url, method === 'POST' ? { json: {} } : {})
      expect([url, res.status, res.text]).toEqual([url, 404, 'wiki fallthrough'])
    }
  })

  it('challenges unauthenticated MCP requests with the metadata location', async () => {
    const res = await request('POST', '/mcp', { json: { jsonrpc: '2.0', id: 1, method: 'initialize' } })
    expect(res.status).toBe(401)
    expect(res.headers['www-authenticate']).toBe(`Bearer resource_metadata="${HOST}/.well-known/oauth-protected-resource/mcp"`)
  })

  it('ignores the browser session on the MCP endpoint', async () => {
    const res = await request('POST', '/mcp', { headers: as(1), json: { jsonrpc: '2.0', id: 1, method: 'tools/list' } })
    expect(res.status).toBe(401)
  })
})

describe('mcp/registration', () => {
  it('rate limits registration', async () => {
    let last
    for (let i = 0; i < 31; i++) { last = await register() }
    expect(last.status).toBe(429)
  })

  it('registers a public client', async () => {
    const res = await register()
    expect(res.status).toBe(201)
    expect(res.body.client_id).toEqual(expect.any(String))
    expect(res.body.client_secret).toBeUndefined()
    expect(res.body.token_endpoint_auth_method).toBe('none')
  })

  it.each([
    ['plain http', 'http://evil.example/cb'],
    ['javascript scheme', 'javascript:alert(1)'],
    ['data scheme', 'data:text/html,hi'],
    ['fragment', 'https://app.example/cb#frag'],
    ['credentials', 'https://user:pw@app.example/cb'],
    ['not a url', 'nope']
  ])('rejects redirect uri with %s', async (label, uri) => {
    const res = await register({ redirect_uris: [uri] })
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('invalid_redirect_uri')
  })

  it('accepts loopback and app scheme redirects', async () => {
    const res = await register({ redirect_uris: ['http://localhost:3334/callback', 'http://127.0.0.1/cb', 'cursor://anysphere.cursor-mcp/oauth/callback'] })
    expect(res.status).toBe(201)
  })

  it('rejects confidential clients', async () => {
    const res = await register({ token_endpoint_auth_method: 'client_secret_post' })
    expect(res.status).toBe(400)
  })
})

describe('mcp/authorization', () => {
  it('never redirects to an unregistered redirect uri', async () => {
    const client = (await register()).body
    const res = await request('GET', authorizeUrl(client.client_id, pkce().challenge, { redirect_uri: 'https://evil.example/cb' }), { headers: as(3) })
    expect(res.status).toBe(400)
    expect(res.headers.location).toBeUndefined()
  })

  it('rejects unknown clients without redirecting', async () => {
    const res = await request('GET', authorizeUrl('nope', pkce().challenge), { headers: as(3) })
    expect(res.status).toBe(400)
    expect(res.headers.location).toBeUndefined()
  })

  it('requires PKCE S256', async () => {
    const client = (await register()).body
    const res = await request('GET', authorizeUrl(client.client_id, pkce().challenge, { code_challenge_method: 'plain' }), { headers: as(3) })
    const location = new URL(res.headers.location)
    expect(location.origin + location.pathname).toBe(REDIRECT)
    expect(location.searchParams.get('error')).toBe('invalid_request')
    expect(location.searchParams.get('state')).toBe('xyz')
  })

  it('sends guests to the login page and back', async () => {
    const client = (await register()).body
    const res = await request('GET', authorizeUrl(client.client_id, pkce().challenge))
    expect(res.status).toBe(302)
    expect(res.headers.location).toBe('/login')
    const cookie = decodeURIComponent(res.headers['set-cookie'][0].split(';')[0])
    expect(cookie.startsWith('loginRedirect=/oauth/authorize?')).toBe(true)
    // Must survive the login page's open-redirect check
    expect(cookie.includes('://')).toBe(false)
  })

  it('shows a consent screen naming the application, user and destination', async () => {
    const client = (await register({ client_name: '<b>Claude</b>' })).body
    const res = await request('GET', authorizeUrl(client.client_id, pkce().challenge), { headers: as(3) })
    expect(res.status).toBe(200)
    expect(res.text).toContain('&lt;b&gt;Claude&lt;/b&gt;')
    expect(res.text).not.toContain('<b>Claude</b>')
    expect(res.text).toContain('Erin Editor')
    expect(res.text).toContain('https://claude.ai')
    expect(res.headers['x-frame-options']).toBe('deny')
    expect(res.headers['content-security-policy']).toContain(`frame-ancestors 'none'`)
  })

  it('refuses a consent form replayed by a different user', async () => {
    const client = (await register()).body
    const consent = await request('GET', authorizeUrl(client.client_id, pkce().challenge), { headers: as(3) })
    const form = { request: hidden(consent.text, 'request'), signature: hidden(consent.text, 'signature'), decision: 'approve' }
    expect((await request('POST', '/oauth/authorize', { headers: as(4), form })).status).toBe(400)
    expect((await request('POST', '/oauth/authorize', { form })).status).toBe(400)
  })

  it('refuses a tampered consent form', async () => {
    const client = (await register()).body
    const consent = await request('GET', authorizeUrl(client.client_id, pkce().challenge), { headers: as(3) })
    const original = JSON.parse(Buffer.from(hidden(consent.text, 'request'), 'base64url').toString())
    const forged = Buffer.from(JSON.stringify({ ...original, userId: 1 })).toString('base64url')
    const res = await request('POST', '/oauth/authorize', { headers: as(1), form: { request: forged, signature: hidden(consent.text, 'signature'), decision: 'approve' } })
    expect(res.status).toBe(400)
  })

  it('reports denial to the client', async () => {
    const client = (await register()).body
    const consent = await request('GET', authorizeUrl(client.client_id, pkce().challenge), { headers: as(3) })
    const res = await request('POST', '/oauth/authorize', { headers: as(3), form: { request: hidden(consent.text, 'request'), signature: hidden(consent.text, 'signature'), decision: 'deny' } })
    expect(new URL(res.headers.location).searchParams.get('error')).toBe('access_denied')
  })
})

describe('mcp/tokens', () => {
  it('completes the flow and returns opaque tokens', async () => {
    const { tokens, status } = await connect(3)
    expect(status).toBe(200)
    expect(tokens.token_type).toBe('Bearer')
    expect(tokens.scope).toBe('wiki:read wiki:write')
    expect(tokens.access_token).toMatch(/^wmcp_at_/)
    expect(tokens.refresh_token).toMatch(/^wmcp_rt_/)
    // Only hashes are stored
    const stored = await knex('mcpTokens').select('hash')
    expect(stored.some(t => t.hash.includes(tokens.access_token) || tokens.access_token.includes(t.hash))).toBe(false)
  })

  it('rejects a wrong PKCE verifier and burns the code', async () => {
    const client = (await register()).body
    const { verifier, challenge } = pkce()
    const consent = await request('GET', authorizeUrl(client.client_id, challenge), { headers: as(3) })
    const decision = await request('POST', '/oauth/authorize', { headers: as(3), form: { request: hidden(consent.text, 'request'), signature: hidden(consent.text, 'signature'), decision: 'approve' } })
    const code = new URL(decision.headers.location).searchParams.get('code')
    const form = { grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: REDIRECT }
    const bad = await request('POST', '/oauth/token', { form: { ...form, code_verifier: pkce().verifier } })
    expect(bad.status).toBe(400)
    expect(bad.body.error).toBe('invalid_grant')
    const retry = await request('POST', '/oauth/token', { form: { ...form, code_verifier: verifier } })
    expect(retry.status).toBe(400)
  })

  it('revokes everything when an authorization code is replayed', async () => {
    const { client, code, verifier, tokens } = await connect(3)
    const replay = await request('POST', '/oauth/token', { form: { grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: REDIRECT, code_verifier: verifier } })
    expect(replay.status).toBe(400)
    // The code row is gone after a successful exchange, so the first tokens stay valid
    expect((await rpc(tokens.access_token, 'ping')).status).toBe(200)
  })

  it('does not let another client redeem a code', async () => {
    const client = (await register()).body
    const other = (await register()).body
    const { verifier, challenge } = pkce()
    const consent = await request('GET', authorizeUrl(client.client_id, challenge), { headers: as(3) })
    const decision = await request('POST', '/oauth/authorize', { headers: as(3), form: { request: hidden(consent.text, 'request'), signature: hidden(consent.text, 'signature'), decision: 'approve' } })
    const code = new URL(decision.headers.location).searchParams.get('code')
    const res = await request('POST', '/oauth/token', { form: { grant_type: 'authorization_code', client_id: other.client_id, code, redirect_uri: REDIRECT, code_verifier: verifier } })
    expect(res.status).toBe(400)
  })

  it('rotates refresh tokens and kills the connection on reuse', async () => {
    const { client, tokens } = await connect(3)
    const form = { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token }
    const refreshed = await request('POST', '/oauth/token', { form })
    expect(refreshed.status).toBe(200)
    expect(refreshed.body.refresh_token).not.toBe(tokens.refresh_token)
    // The previous access token stops working once rotated
    expect((await rpc(tokens.access_token, 'ping')).status).toBe(401)
    expect((await rpc(refreshed.body.access_token, 'ping')).status).toBe(200)

    const reuse = await request('POST', '/oauth/token', { form })
    expect(reuse.status).toBe(400)
    expect((await rpc(refreshed.body.access_token, 'ping')).status).toBe(401)
  })

  it('stops working as soon as the user is deactivated', async () => {
    const { tokens } = await connect(3)
    expect((await rpc(tokens.access_token, 'ping')).status).toBe(200)
    users[3].isActive = false
    expect((await rpc(tokens.access_token, 'ping')).status).toBe(401)
  })

  it('lets the user review and revoke a connection', async () => {
    const { tokens } = await connect(4)
    const list = await request('GET', '/oauth/connections', { headers: as(4) })
    expect(list.text).toContain('Claude')
    const form = { grant: hidden(list.text, 'grant'), csrf: hidden(list.text, 'csrf') }
    // Someone else cannot revoke it
    expect((await request('POST', '/oauth/connections/revoke', { headers: as(3), form })).status).toBe(400)
    expect((await rpc(tokens.access_token, 'ping')).status).toBe(200)
    expect((await request('POST', '/oauth/connections/revoke', { headers: as(4), form })).status).toBe(302)
    expect((await rpc(tokens.access_token, 'ping')).status).toBe(401)
  })

  it('supports token revocation by the client', async () => {
    const { tokens } = await connect(3)
    await request('POST', '/oauth/revoke', { form: { token: tokens.refresh_token } })
    expect((await rpc(tokens.access_token, 'ping')).status).toBe(401)
  })
})

describe('mcp/protocol', () => {
  it('initializes and lists tools', async () => {
    const { tokens } = await connect(3)
    const init = await rpc(tokens.access_token, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } })
    expect(init.body.result.protocolVersion).toBe('2025-06-18')
    expect(init.body.result.capabilities.tools).toBeDefined()

    const note = await request('POST', '/mcp', { headers: { authorization: `Bearer ${tokens.access_token}` }, json: { jsonrpc: '2.0', method: 'notifications/initialized' } })
    expect(note.status).toBe(202)

    const list = await rpc(tokens.access_token, 'tools/list')
    const names = list.body.result.tools.map(t => t.name)
    expect(names).toEqual(expect.arrayContaining(['search_pages', 'read_page', 'edit_page', 'delete_page']))
    expect(list.body.result.tools.find(t => t.name === 'read_page').annotations.readOnlyHint).toBe(true)
    expect(list.body.result.tools.find(t => t.name === 'delete_page').annotations.destructiveHint).toBe(true)
  })

  it('answers unknown methods and rejects other HTTP methods', async () => {
    const { tokens } = await connect(3)
    expect((await rpc(tokens.access_token, 'resources/list')).body.error.code).toBe(-32601)
    expect((await request('GET', '/mcp', { headers: { authorization: `Bearer ${tokens.access_token}` } })).status).toBe(405)
  })

  it('hides and refuses write tools on a read-only connection', async () => {
    const { tokens } = await connect(3, { allowWrite: false })
    expect(tokens.scope).toBe('wiki:read')
    const list = await rpc(tokens.access_token, 'tools/list')
    expect(list.body.result.tools.map(t => t.name)).not.toContain('update_page')
    const res = await rpc(tokens.access_token, 'tools/call', { name: 'update_page', arguments: { path: 'team/notes', content: 'x' } })
    expect(res.body.error.code).toBe(-32602)
    expect(WIKI.models.pages.updatePage).not.toHaveBeenCalled()
  })
})

describe('mcp/tools', () => {
  it('reads pages the user can read', async () => {
    const { tokens } = await connect(3)
    const result = await callTool(tokens.access_token, 'read_page', { path: 'team/notes' })
    expect(result.isError).toBeUndefined()
    expect(result.content[0].text).toContain('alpha beta alpha')
    expect(result.content[0].text).toContain('updated: 2026-01-02T00:00:00.000Z')
  })

  it('makes forbidden pages indistinguishable from missing ones', async () => {
    const { tokens } = await connect(3)
    const forbidden = await callTool(tokens.access_token, 'read_page', { path: 'hr/salaries' })
    const missing = await callTool(tokens.access_token, 'read_page', { path: 'hr/nothing' })
    expect(forbidden.isError).toBe(true)
    expect(forbidden.content[0].text).not.toContain('secret')
    expect(forbidden.content[0].text.replace('salaries', 'X')).toBe(missing.content[0].text.replace('nothing', 'X'))
  })

  it('filters search results by page rules', async () => {
    const { tokens } = await connect(3)
    const text = (await callTool(tokens.access_token, 'search_pages', { query: 'anything' })).content[0].text
    expect(text).toContain('team/notes')
    expect(text).not.toContain('hr/salaries')
  })

  it('only gives rendered text to users without source access, and hides drafts from them', async () => {
    const { tokens } = await connect(4)
    const page = await callTool(tokens.access_token, 'read_page', { path: 'hr/salaries' })
    expect(page.content[0].text).toContain('rendered text')
    expect(page.content[0].text).toContain('secret numbers')
    const draft = await callTool(tokens.access_token, 'read_page', { path: 'team/draft' })
    expect(draft.isError).toBe(true)
  })

  it('refuses edits from users who cannot write, even with the write scope', async () => {
    const { tokens } = await connect(4)
    const result = await callTool(tokens.access_token, 'update_page', { path: 'team/notes', content: 'pwned' })
    expect(result.isError).toBe(true)
    expect(WIKI.models.pages.updatePage).not.toHaveBeenCalled()
  })

  it('applies exact edits and preserves everything else, including page scripts', async () => {
    const { tokens } = await connect(3)
    const result = await callTool(tokens.access_token, 'edit_page', { path: 'team/notes', edits: [{ old_text: 'beta', new_text: 'gamma' }] })
    expect(result.isError).toBeUndefined()
    const saved = WIKI.models.pages.updatePage.mock.calls[0][0]
    expect(saved.content).toBe('alpha gamma alpha')
    expect(saved.title).toBe('Title 10')
    expect(saved.scriptJs).toBe('alert(1)')
    expect(saved.scriptCss).toBe('body{}')
    expect(saved.path).toBe('team/notes')
    expect(saved.user.id).toBe(3)
  })

  it('refuses ambiguous or missing edit targets without saving', async () => {
    const { tokens } = await connect(3)
    const ambiguous = await callTool(tokens.access_token, 'edit_page', { path: 'team/notes', edits: [{ old_text: 'alpha', new_text: 'x' }] })
    expect(ambiguous.isError).toBe(true)
    const missing = await callTool(tokens.access_token, 'edit_page', { path: 'team/notes', edits: [{ old_text: 'zzz', new_text: 'x' }] })
    expect(missing.isError).toBe(true)
    expect(WIKI.models.pages.updatePage).not.toHaveBeenCalled()

    await callTool(tokens.access_token, 'edit_page', { path: 'team/notes', edits: [{ old_text: 'alpha', new_text: 'x', replace_all: true }] })
    expect(WIKI.models.pages.updatePage.mock.calls[0][0].content).toBe('x beta x')
  })

  it('refuses to overwrite a page that changed since it was read', async () => {
    const { tokens } = await connect(3)
    const result = await callTool(tokens.access_token, 'update_page', { path: 'team/notes', content: 'new', expected_updated_at: '2025-12-31T00:00:00.000Z' })
    expect(result.isError).toBe(true)
    expect(WIKI.models.pages.updatePage).not.toHaveBeenCalled()
  })

  it('requires delete permission and a matching title to delete', async () => {
    const editor = await connect(3)
    const denied = await callTool(editor.tokens.access_token, 'delete_page', { path: 'team/notes', confirm_title: 'Title 10' })
    expect(denied.isError).toBe(true)

    const admin = await connect(1)
    const wrongTitle = await callTool(admin.tokens.access_token, 'delete_page', { path: 'team/notes', confirm_title: 'nope' })
    expect(wrongTitle.isError).toBe(true)
    expect(WIKI.models.pages.deletePage).not.toHaveBeenCalled()

    const ok = await callTool(admin.tokens.access_token, 'delete_page', { path: 'team/notes', confirm_title: 'Title 10' })
    expect(ok.isError).toBeUndefined()
    expect(WIKI.models.pages.deletePage).toHaveBeenCalledWith(expect.objectContaining({ id: 10 }))
  })

  it('validates tool input', async () => {
    const { tokens } = await connect(3)
    expect((await callTool(tokens.access_token, 'read_page', {})).isError).toBe(true)
    expect((await callTool(tokens.access_token, 'read_page', { path: 5 })).isError).toBe(true)
    expect((await callTool(tokens.access_token, 'read_page', { path: 'team/notes', script: 'x' })).isError).toBe(true)
    expect((await callTool(tokens.access_token, 'read_page', { path: 'team/notes', locale: 'zz' })).isError).toBe(true)
  })
})

describe('mcp/assets', () => {
  it('lists only the folders and files the user may read', async () => {
    const { tokens } = await connect(3)
    const root = (await callTool(tokens.access_token, 'list_assets', {})).content[0].text
    expect(root).toContain('[folder] team')
    expect(root).not.toContain('hr')
    const team = (await callTool(tokens.access_token, 'list_assets', { folder: 'team' })).content[0].text
    expect(team).toContain('team/logo.png — image/png')
    const hr = await callTool(tokens.access_token, 'list_assets', { folder: 'hr' })
    expect(hr.isError).toBe(true)
  })

  it('shows images as images and text files as text', async () => {
    const { tokens } = await connect(3)
    const image = await callTool(tokens.access_token, 'view_asset', { path: '/team/logo.png' })
    expect(image.isError).toBeUndefined()
    expect(image.content[1]).toEqual({ type: 'image', data: PNG.toString('base64'), mimeType: 'image/png' })
    const svg = await callTool(tokens.access_token, 'view_asset', { path: 'team/notes.svg' })
    expect(svg.content[0].text).toContain('<svg xmlns')
  })

  it('makes forbidden files indistinguishable from missing ones', async () => {
    const { tokens } = await connect(3)
    const forbidden = await callTool(tokens.access_token, 'view_asset', { path: 'hr/secret.png' })
    const missing = await callTool(tokens.access_token, 'view_asset', { path: 'hr/nothing.png' })
    expect(forbidden.isError).toBe(true)
    expect(forbidden.content[0].text.replace('secret', 'X')).toBe(missing.content[0].text.replace('nothing', 'X'))
    const reader = await connect(4)
    expect((await callTool(reader.tokens.access_token, 'view_asset', { path: 'team/logo.png' })).isError).toBe(true)
  })

  it.each([
    ['denied by a rule', 'team/private.png'],
    ['denied under another spelling', 'team/PRIVATE.PNG'],
    ['denied by a locale-specific rule', 'team/english.png']
  ])('refuses files %s', async (label, assetPath) => {
    const { tokens } = await connect(3)
    expect((await callTool(tokens.access_token, 'view_asset', { path: assetPath })).isError).toBe(true)
    expect((await callTool(tokens.access_token, 'get_asset_download_url', { path: assetPath })).isError).toBe(true)
    const listing = (await callTool(tokens.access_token, 'list_assets', { folder: 'team' })).content[0].text
    expect(listing.toLowerCase()).not.toContain(assetPath.toLowerCase())
  })

  it('does not let concurrent uploads replace each other', async () => {
    const { tokens } = await connect(3)
    const results = await Promise.all(['first', 'second'].map(text => callTool(tokens.access_token, 'upload_asset', { path: 'team/race/same.svg', text })))
    expect(results.filter(r => r.isError).length).toBe(1)
    expect((await knex('assetFolders').where('slug', 'race')).length).toBe(1)
  })

  it('hands out download links for one file that stop working with the user', async () => {
    const { tokens } = await connect(3, { allowWrite: false })
    const result = await callTool(tokens.access_token, 'get_asset_download_url', { path: 'team/logo.png' })
    const link = linkIn(result, 'download')
    const res = await request('GET', link)
    expect(res.status).toBe(200)
    expect(res.data.equals(PNG)).toBe(true)
    expect(res.headers['content-disposition']).toContain('attachment')
    expect(res.headers['x-content-type-options']).toBe('nosniff')
    // Usable more than once while valid, but not as anything else
    expect((await request('GET', link)).status).toBe(200)
    expect((await request('PUT', link.replace('download', 'upload'), { raw: PNG })).status).toBe(404)
    expect((await request('GET', '/mcp/download/wmcp_dl_nope')).status).toBe(404)
    users[3].isActive = false
    expect((await request('GET', link)).status).toBe(404)
  })

  it('uploads through a single-use link, creating folders', async () => {
    const { tokens } = await connect(3)
    const result = await callTool(tokens.access_token, 'create_asset_upload', { path: 'team/Diagrams/Network Map.PNG' })
    expect(result.isError).toBeUndefined()
    expect(result.content[0].text).toContain('team/diagrams/network_map.png')
    const link = linkIn(result, 'upload')

    // A wrongly encoded request does not use up the link
    const json = await request('PUT', link, { json: { file: 'x' } })
    expect(json.status).toBe(415)

    const res = await request('PUT', link, { raw: PNG, headers: { 'content-type': 'application/octet-stream' } })
    expect(res.status).toBe(201)
    expect(res.body).toEqual(expect.objectContaining({ ok: true, path: 'team/diagrams/network_map.png', markdown: '![description](/team/diagrams/network_map.png)' }))
    const stored = await storedAsset('team/diagrams/network_map.png')
    expect(Buffer.from(stored.data).equals(PNG)).toBe(true)
    expect(stored.mime).toBe('image/png')
    expect(WIKI.models.assets.upload).toHaveBeenCalledWith(expect.objectContaining({ assetPath: 'team/diagrams/network_map.png', user: expect.objectContaining({ id: 3 }) }))

    expect((await request('PUT', link, { raw: PNG })).status).toBe(404)
    expect(await fs.readdir(path.join(dataRoot, 'data/uploads'))).toEqual([])
  })

  it('refuses oversized uploads and cleans up', async () => {
    const { tokens } = await connect(3)
    const link = linkIn(await callTool(tokens.access_token, 'create_asset_upload', { path: 'team/big.bin' }), 'upload')
    const res = await request('PUT', link, { raw: Buffer.alloc(5000) })
    expect(res.status).toBe(413)
    // Without a declared length the limit is enforced while streaming
    const streamed = linkIn(await callTool(tokens.access_token, 'create_asset_upload', { path: 'team/big.bin' }), 'upload')
    const chunked = await request('PUT', streamed, { raw: Buffer.alloc(5000), headers: { 'transfer-encoding': 'chunked' } })
    expect(chunked.status).toBe(413)
    expect(await storedAsset('team/big.bin')).toBeNull()
    expect(await fs.readdir(path.join(dataRoot, 'data/uploads'))).toEqual([])
  })

  it('never overwrites a file unless asked', async () => {
    const { tokens } = await connect(3)
    const refused = await callTool(tokens.access_token, 'create_asset_upload', { path: 'team/logo.png' })
    expect(refused.isError).toBe(true)

    // A file created after the link was issued is not overwritten either
    const link = linkIn(await callTool(tokens.access_token, 'create_asset_upload', { path: 'team/later.png' }), 'upload')
    await callTool(tokens.access_token, 'upload_asset', { path: 'team/later.png', base64: PNG.toString('base64') })
    const late = await request('PUT', link, { raw: Buffer.from('other') })
    expect(late.status).toBe(409)
    expect(Buffer.from((await storedAsset('team/later.png')).data).equals(PNG)).toBe(true)

    const replace = await callTool(tokens.access_token, 'upload_asset', { path: 'team/logo.png', text: 'replaced', overwrite: true })
    expect(replace.content[0].text).toContain('Replaced team/logo.png')
  })

  it('uploads small inline files', async () => {
    const { tokens } = await connect(3)
    const svg = await callTool(tokens.access_token, 'upload_asset', { path: 'team/flow.svg', text: '<svg/>' })
    expect(svg.isError).toBeUndefined()
    expect(svg.content[0].text).toContain('![description](/team/flow.svg)')
    expect(Buffer.from((await storedAsset('team/flow.svg')).data).toString()).toBe('<svg/>')
    expect((await callTool(tokens.access_token, 'upload_asset', { path: 'team/x.png' })).isError).toBe(true)
    expect((await callTool(tokens.access_token, 'upload_asset', { path: 'team/x.png', base64: 'not base64!' })).isError).toBe(true)
  })

  it.each([
    ['outside the allowed folders', 'hr/x.png'],
    ['a locale-like first segment', 'en/x.png'],
    ['a reserved first segment', 'img/x.png'],
    ['a wiki route', 'mcp/upload/x.png'],
    ['a page extension', 'team/x.md'],
    ['no extension', 'team/readme'],
    ['path traversal', 'team/../hr/x.png'],
    ['odd folder names', 'team/a b%/x.png']
  ])('refuses uploads to %s', async (label, assetPath) => {
    const { tokens } = await connect(3)
    const result = await callTool(tokens.access_token, 'upload_asset', { path: assetPath, text: 'x' })
    expect(result.isError).toBe(true)
    expect(WIKI.models.assets.upload).not.toHaveBeenCalled()
  })

  it('offers no uploads on a read-only connection, and a link dies with the write scope', async () => {
    const { tokens } = await connect(3, { allowWrite: false })
    const names = (await rpc(tokens.access_token, 'tools/list')).body.result.tools.map(t => t.name)
    expect(names).toEqual(expect.arrayContaining(['list_assets', 'view_asset', 'get_asset_download_url']))
    expect(names).not.toContain('create_asset_upload')
    expect(names).not.toContain('upload_asset')

    const writer = await connect(3)
    const link = linkIn(await callTool(writer.tokens.access_token, 'create_asset_upload', { path: 'team/a.png' }), 'upload')
    await request('POST', '/oauth/revoke', { form: { token: writer.tokens.refresh_token } })
    expect((await request('PUT', link, { raw: PNG })).status).toBe(404)
  })
})
