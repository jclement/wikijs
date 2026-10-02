const _ = require('lodash')
const fs = require('fs-extra')
const TurndownService = require('turndown')
const assets = require('./assets')
const oauth = require('./oauth')

/* global WIKI */

// MCP tools. Every tool runs as the connected user: access is decided by the same
// WIKI.auth.checkAccess / page model checks the web UI and GraphQL API use, further
// narrowed by the OAuth scopes the user granted. No administrative operation is exposed.

const MAX_CONTENT_CHARS = 200000
const MAX_LIST = 200
const MAX_INLINE_IMAGE = 3 * 1024 * 1024
const MAX_INLINE_TEXT = 1024 * 1024
const MAX_INLINE_UPLOAD = 1024 * 1024

class ToolError extends Error {}

const str = (description, extra = {}) => ({ type: 'string', description, ...extra })
const LOCALE = str('Locale code of the page, e.g. "en". Defaults to the wiki\'s main locale.', { maxLength: 10 })
const PATH = str('Page path without locale or leading slash, e.g. "engineering/onboarding".', { maxLength: 255 })

// ----------------------------------------
// Helpers
// ----------------------------------------

const cleanPath = value => _.trim(_.toString(value).trim(), '/')

const getLocale = args => {
  const locale = args.locale || WIKI.config.lang.code
  const known = _.uniq([WIKI.config.lang.code, ...(_.get(WIKI.config, 'lang.namespaces') || [])])
  if (!known.includes(locale)) {
    throw new ToolError(`Unknown locale "${locale}". Available locales: ${known.join(', ')}.`)
  }
  return locale
}

const can = (ctx, permissions, page) => WIKI.auth.checkAccess(ctx.user, permissions, {
  path: page.path,
  locale: page.localeCode || page.locale,
  tags: page.tags || []
})

const isTrue = v => v === true || v === 1

const isPublished = page => {
  if (!isTrue(page.isPublished)) { return false }
  const now = new Date()
  if (!_.isEmpty(page.publishStartDate) && new Date(page.publishStartDate) > now) { return false }
  if (!_.isEmpty(page.publishEndDate) && new Date(page.publishEndDate) < now) { return false }
  return true
}

// Unpublished pages are only visible to those who can edit them, as in the web UI
const canSee = (ctx, page) => can(ctx, ['read:pages'], page) && (isPublished(page) || can(ctx, ['write:pages'], page))

const pageUrl = page => `${_.trimEnd(_.toString(WIKI.config.host), '/')}/${page.localeCode || page.locale}/${page.path}`

const pageExtra = page => {
  if (_.isPlainObject(page.extra)) { return page.extra }
  try {
    return JSON.parse(page.extra) || {}
  } catch (err) {
    return {}
  }
}

/**
 * Load a page the user can see. Missing and inaccessible pages are indistinguishable on purpose.
 */
const loadPage = async (ctx, args) => {
  const locale = getLocale(args)
  const path = cleanPath(args.path)
  const page = path ? await WIKI.models.pages.getPageFromDb({ path, locale }) : null
  if (!page || !canSee(ctx, page)) {
    throw new ToolError(`No page at "${locale}/${path}", or you do not have access to it.`)
  }
  return page
}

const requirePermission = (ctx, permissions, page, action) => {
  if (!can(ctx, permissions, page)) {
    throw new ToolError(`You do not have permission to ${action} "${page.localeCode}/${page.path}".`)
  }
}

const audit = (ctx, action, target) => {
  WIKI.logger.info(`MCP: user ${ctx.user.id} via "${ctx.clientName}" ${action} ${target}`)
}

const describePage = page => [
  `title: ${page.title}`,
  `path: ${page.path}`,
  `locale: ${page.localeCode}`,
  `url: ${pageUrl(page)}`,
  `description: ${page.description || ''}`,
  `tags: ${_.map(page.tags, 'tag').join(', ')}`,
  `format: ${page.contentType}`,
  `published: ${isPublished(page)}`,
  `created: ${page.createdAt} by ${page.creatorName}`,
  `updated: ${page.updatedAt} by ${page.authorName}`
].join('\n')

const savedSummary = (verb, page) => `${verb} "${page.title}" at ${page.localeCode}/${page.path}\nurl: ${pageUrl(page)}\nupdated: ${page.updatedAt}`

const checkNotStale = (page, expected) => {
  if (expected && expected !== page.updatedAt) {
    throw new ToolError(`The page was changed at ${page.updatedAt}, after the version you read (${expected}). Read it again and re-apply your change.`)
  }
}

/**
 * Save a page through the model, keeping every property the caller did not change.
 * Page scripts and styles are passed through untouched: they cannot be set via MCP.
 */
const savePage = async (ctx, page, changes) => {
  const extra = pageExtra(page)
  try {
    return await WIKI.models.pages.updatePage({
      id: page.id,
      content: _.has(changes, 'content') ? changes.content : page.content,
      title: _.has(changes, 'title') ? changes.title : page.title,
      description: _.has(changes, 'description') ? changes.description : page.description,
      tags: _.has(changes, 'tags') ? changes.tags : _.map(page.tags, 'tag'),
      isPublished: _.has(changes, 'isPublished') ? changes.isPublished : isTrue(page.isPublished),
      publishStartDate: page.publishStartDate,
      publishEndDate: page.publishEndDate,
      scriptJs: extra.js || '',
      scriptCss: extra.css || '',
      locale: page.localeCode,
      path: page.path,
      user: ctx.user
    })
  } catch (err) {
    throw new ToolError(err.message)
  }
}

const listVisiblePages = async (ctx, locale) => {
  const pages = await WIKI.models.pages.query()
    .column(['pages.id', 'path', 'localeCode', 'title', 'description', 'isPublished', 'publishStartDate', 'publishEndDate', 'updatedAt'])
    .withGraphFetched('tags')
    .modifyGraph('tags', builder => {
      builder.select('tag')
    })
    .where('localeCode', locale)
  return pages.filter(page => canSee(ctx, page))
}

/**
 * Run asset operations, turning their expected failures into tool errors
 */
const assetOp = async fn => {
  try {
    return await fn()
  } catch (err) {
    if (err instanceof assets.AssetError) {
      throw new ToolError(err.message)
    }
    throw err
  }
}

const formatSize = bytes => bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`

const assetUrl = assetPath => `${oauth.baseUrl()}/${assetPath}`

const describeAsset = asset => [
  `path: ${asset.path}`,
  `url: ${assetUrl(asset.path)}`,
  `type: ${assets.mimeOf(asset.filename)}`,
  `size: ${formatSize(_.toSafeInteger(asset.fileSize))}`,
  `updated: ${asset.updatedAt}`
].join('\n')

const storedSummary = (ctx, stored) => {
  audit(ctx, stored.replaced ? 'replaced file' : 'uploaded file', `${stored.path} (${stored.size} bytes)`)
  return [
    `${stored.replaced ? 'Replaced' : 'Uploaded'} ${stored.path} (${formatSize(stored.size)})`,
    `url: ${assetUrl(stored.path)}`,
    `Reference it in Markdown as: ${assets.markdownFor(stored.path)}`
  ].join('\n')
}

const notViewableReason = (mime, size) => assets.INLINE_IMAGE_TYPES.includes(mime) ? `images over ${formatSize(MAX_INLINE_IMAGE)} are not shown` : (size > MAX_INLINE_TEXT ? 'too large' : `${mime} is not viewable`)

const pageLine = page => `- ${page.localeCode || page.locale}/${page.path} — ${page.title}${page.description ? `: ${page.description}` : ''}`

// ----------------------------------------
// Tools
// ----------------------------------------

const tools = [
  {
    name: 'whoami',
    title: 'Who am I',
    description: 'Show which wiki user this connection acts as, what it has been allowed to do, and the wiki\'s locales. Call this first if unsure what you can do.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: { type: 'object', properties: {} },
    async handler (args, ctx) {
      const perms = ctx.user.permissions
      const contentPerms = perms.includes('manage:system') ? ['all content (administrator)'] : perms.filter(p => /:(pages|source|history|assets)$/.test(p))
      return [
        `wiki: ${WIKI.config.title} (${_.trimEnd(_.toString(WIKI.config.host), '/')})`,
        `user: ${ctx.user.name}`,
        `connection scopes: ${ctx.scopes.join(', ')}${ctx.scopes.includes('wiki:write') ? '' : ' (read-only)'}`,
        `content permissions: ${contentPerms.join(', ') || 'none'} (individual pages may be further restricted by page rules)`,
        `main locale: ${WIKI.config.lang.code}`,
        `locales: ${_.uniq([WIKI.config.lang.code, ...(_.get(WIKI.config, 'lang.namespaces') || [])]).join(', ')}`
      ].join('\n')
    }
  },
  {
    name: 'search_pages',
    title: 'Search pages',
    description: 'Full-text search of the wiki. Returns matching pages (path, title, description) that you can then open with read_page.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: {
        query: str('Search terms.', { maxLength: 300 }),
        locale: str('Only search this locale. Omit to search all locales.', { maxLength: 10 }),
        path_prefix: str('Only search pages whose path starts with this prefix, e.g. "engineering".', { maxLength: 255 })
      },
      required: ['query']
    },
    async handler (args, ctx) {
      const query = args.query.trim()
      if (query.length < 2 || !WIKI.data.searchEngine) {
        throw new ToolError(query.length < 2 ? 'Search query is too short.' : 'Search is not available on this wiki.')
      }
      const resp = await WIKI.data.searchEngine.query(query, {
        query,
        locale: args.locale,
        path: args.path_prefix ? cleanPath(args.path_prefix) : undefined
      })
      const results = _.filter(resp.results, r => can(ctx, ['read:pages'], r)).slice(0, 25)
      if (results.length < 1) {
        const suggestions = _.compact(resp.suggestions).slice(0, 5)
        return `No pages match "${query}".${suggestions.length > 0 ? ` Did you mean: ${suggestions.join(', ')}?` : ''}`
      }
      return `${results.length} result(s) for "${query}":\n${results.map(pageLine).join('\n')}`
    }
  },
  {
    name: 'list_pages',
    title: 'List pages',
    description: 'List pages you can read, optionally limited to a path prefix or tags. Use browse_tree to explore the folder structure level by level instead.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: {
        locale: LOCALE,
        path_prefix: str('Only list pages whose path starts with this prefix.', { maxLength: 255 }),
        tags: { type: 'array', items: { type: 'string' }, description: 'Only list pages that have all of these tags.' },
        order_by: str('Sort order.', { enum: ['path', 'title', 'updated'] }),
        limit: { type: 'integer', description: `Maximum number of pages to return (default 50, max ${MAX_LIST}).` }
      }
    },
    async handler (args, ctx) {
      const locale = getLocale(args)
      const prefix = cleanPath(args.path_prefix || '')
      const tags = (args.tags || []).map(t => t.trim().toLowerCase())
      let pages = (await listVisiblePages(ctx, locale)).filter(page => {
        return (!prefix || page.path === prefix || page.path.startsWith(`${prefix}/`)) &&
          tags.every(t => _.some(page.tags, ['tag', t]))
      })
      pages = args.order_by === 'updated' ? _.orderBy(pages, ['updatedAt'], ['desc']) : _.sortBy(pages, [args.order_by || 'path'])
      const limit = _.clamp(args.limit || 50, 1, MAX_LIST)
      const shown = pages.slice(0, limit)
      if (shown.length < 1) { return 'No pages found.' }
      const lines = shown.map(page => args.order_by === 'updated' ? `${pageLine(page)} (updated ${page.updatedAt})` : pageLine(page))
      return `${shown.length} of ${pages.length} page(s):\n${lines.join('\n')}`
    }
  },
  {
    name: 'browse_tree',
    title: 'Browse page tree',
    description: 'List the folders and pages directly under a path, like a directory listing. Omit path for the top level.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: {
        path: str('Folder path to list. Omit for the top level.', { maxLength: 255 }),
        locale: LOCALE
      }
    },
    async handler (args, ctx) {
      const locale = getLocale(args)
      const path = cleanPath(args.path || '')
      let parent = null
      if (path) {
        const entry = await WIKI.models.knex('pageTree').first('id').where({ path, localeCode: locale })
        if (!entry) {
          throw new ToolError(`Nothing found at "${locale}/${path}".`)
        }
        parent = entry.id
      }
      const visiblePaths = new Set((await listVisiblePages(ctx, locale)).map(p => p.path))
      const entries = await WIKI.models.knex('pageTree').where('localeCode', locale).where(builder => {
        if (parent) {
          builder.where('parent', parent)
        } else {
          builder.whereNull('parent')
        }
      }).orderBy([{ column: 'isFolder', order: 'desc' }, 'title'])
      // A folder is shown only if it holds at least one page the user can see
      const lines = entries.filter(e => {
        const hasPage = e.pageId && visiblePaths.has(e.path)
        const hasChildren = isTrue(e.isFolder) && [...visiblePaths].some(p => p.startsWith(`${e.path}/`))
        e.visiblePage = hasPage
        e.visibleFolder = hasChildren
        return hasPage || hasChildren
      }).map(e => `- ${e.visibleFolder ? '[folder' + (e.visiblePage ? ' + page' : '') + ']' : '[page]'} ${e.path} — ${e.title}`)
      return lines.length > 0 ? `Contents of ${locale}/${path}:\n${lines.join('\n')}` : `Nothing visible under "${locale}/${path}".`
    }
  },
  {
    name: 'read_page',
    title: 'Read page',
    description: 'Read a page: its metadata followed by its source (usually Markdown). The "updated" timestamp can be passed to update_page / edit_page as expected_updated_at to avoid overwriting someone else\'s change.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: { path: PATH, locale: LOCALE },
      required: ['path']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      let body
      let note = ''
      if (can(ctx, ['read:source'], page)) {
        body = page.content
      } else {
        // Without source access the user only ever sees the rendered page
        body = new TurndownService({ headingStyle: 'atx', codeBlockStyle: 'fenced' }).remove(['script', 'style']).turndown(page.render || '')
        note = '\nnote: you do not have permission to view this page\'s source, so this is its rendered text.'
      }
      if (body.length > MAX_CONTENT_CHARS) {
        body = body.slice(0, MAX_CONTENT_CHARS)
        note += `\nnote: content truncated to the first ${MAX_CONTENT_CHARS} characters.`
      }
      return `${describePage(page)}${note}\n---\n${body}`
    }
  },
  {
    name: 'get_page_history',
    title: 'Get page history',
    description: 'List the past versions of a page (newest first). Use get_page_version to read one, or restore_page_version to roll back.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: { path: PATH, locale: LOCALE },
      required: ['path']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      requirePermission(ctx, ['read:history'], page, 'view the history of')
      const history = await WIKI.models.pageHistory.getHistory({ pageId: page.id, offsetPage: 0, offsetSize: 50 })
      if (history.trail.length < 1) {
        return `"${page.localeCode}/${page.path}" has no earlier versions. Current version: ${page.updatedAt} by ${page.authorName}.`
      }
      const lines = history.trail.map(v => `- version ${v.versionId}: ${v.versionDate} by ${v.authorName} (${v.actionType}${v.actionType === 'move' ? ` from ${v.valueBefore} to ${v.valueAfter}` : ''})`)
      return `Current version: ${page.updatedAt} by ${page.authorName}\n${history.total} earlier version(s)${history.total > lines.length ? `, showing the latest ${lines.length}` : ''}:\n${lines.join('\n')}`
    }
  },
  {
    name: 'get_page_version',
    title: 'Get page version',
    description: 'Read the content of a past version of a page, using a version id from get_page_history.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: {
        path: PATH,
        locale: LOCALE,
        version_id: { type: 'integer', description: 'Version id from get_page_history.' }
      },
      required: ['path', 'version_id']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      requirePermission(ctx, ['read:history'], page, 'view the history of')
      const version = await WIKI.models.pageHistory.getVersion({ pageId: page.id, versionId: args.version_id })
      if (!version) {
        throw new ToolError(`Version ${args.version_id} does not exist for this page.`)
      }
      return [
        `title: ${version.title}`,
        `path: ${version.path}`,
        `version: ${version.versionId} (${version.action}) from ${version.versionDate} by ${version.authorName}`,
        `format: ${version.contentType}`,
        '---',
        _.toString(version.content).slice(0, MAX_CONTENT_CHARS)
      ].join('\n')
    }
  },
  {
    name: 'list_tags',
    title: 'List tags',
    description: 'List the tags used on pages you can read. Use list_pages with tags to find the pages.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: { locale: LOCALE }
    },
    async handler (args, ctx) {
      const pages = await listVisiblePages(ctx, getLocale(args))
      const counts = _.countBy(_.flatMap(pages, p => _.map(p.tags, 'tag')))
      const tags = _.sortBy(_.keys(counts))
      return tags.length > 0 ? tags.map(t => `- ${t} (${counts[t]})`).join('\n') : 'No tags found.'
    }
  },
  {
    name: 'list_assets',
    title: 'List files',
    description: 'List the uploaded files (images, documents) and subfolders in a folder of the wiki\'s file library. Omit folder for the top level.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: {
        folder: str('Folder path, e.g. "diagrams/network". Omit for the top level.', { maxLength: 255 })
      }
    },
    async handler (args, ctx) {
      const listing = await assetOp(() => assets.list(ctx.user, args.folder))
      const lines = [
        ...listing.folders.map(p => `- [folder] ${p}`),
        ...listing.files.slice(0, MAX_LIST).map(f => `- [file] ${f.path} — ${assets.mimeOf(f.filename)}, ${formatSize(_.toSafeInteger(f.fileSize))}, updated ${f.updatedAt}`)
      ]
      if (lines.length < 1) {
        return `Nothing visible in /${listing.path}.`
      }
      const more = listing.files.length > MAX_LIST ? `\n(showing the first ${MAX_LIST} of ${listing.files.length} files)` : ''
      return `Contents of /${listing.path}:\n${lines.join('\n')}${more}`
    }
  },
  {
    name: 'view_asset',
    title: 'View file',
    description: 'Look at an uploaded file, such as an image referenced by a page (e.g. "/diagrams/flow.png" → path "diagrams/flow.png"). Images (PNG, JPEG, GIF, WebP) are returned as images and text files as text; for anything else use get_asset_download_url.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: { path: str('File path as it appears in the wiki URL, without leading slash.', { maxLength: 255 }) },
      required: ['path']
    },
    async handler (args, ctx) {
      const asset = await assetOp(() => assets.findReadable(ctx.user, args.path))
      const mime = assets.mimeOf(asset.filename)
      const size = _.toSafeInteger(asset.fileSize)
      if (assets.INLINE_IMAGE_TYPES.includes(mime) && size <= MAX_INLINE_IMAGE) {
        const data = await assetOp(() => assets.readData(asset))
        return {
          content: [
            { type: 'text', text: describeAsset(asset) },
            { type: 'image', data: data.toString('base64'), mimeType: mime }
          ]
        }
      }
      if (assets.isText(asset.filename) && size <= MAX_INLINE_TEXT) {
        let text = (await assetOp(() => assets.readData(asset))).toString('utf8')
        let note = ''
        if (text.length > MAX_CONTENT_CHARS) {
          text = text.slice(0, MAX_CONTENT_CHARS)
          note = `\nnote: content truncated to the first ${MAX_CONTENT_CHARS} characters.`
        }
        return `${describeAsset(asset)}${note}\n---\n${text}`
      }
      return `${describeAsset(asset)}\nnote: this file cannot be shown here (${notViewableReason(mime, size)}). Use get_asset_download_url to download it.`
    }
  },
  {
    name: 'get_asset_download_url',
    title: 'Get file download link',
    description: 'Get a short-lived link (valid 5 minutes) that downloads an uploaded file without signing in, e.g. with curl. The link only grants access to that one file.',
    scope: 'wiki:read',
    readOnly: true,
    inputSchema: {
      type: 'object',
      properties: { path: str('File path as it appears in the wiki URL, without leading slash.', { maxLength: 255 }) },
      required: ['path']
    },
    async handler (args, ctx) {
      const asset = await assetOp(() => assets.findReadable(ctx.user, args.path))
      const token = await oauth.createFileToken({ grantId: ctx.grantId, kind: 'download', scope: 'wiki:read', assetPath: asset.path })
      const url = `${oauth.baseUrl()}/mcp/download/${token}`
      return [
        describeAsset(asset),
        `download url (valid ${oauth.DOWNLOAD_TTL / 60} minutes): ${url}`,
        `example: curl -sSf -o ${asset.filename} "${url}"`
      ].join('\n')
    }
  },
  {
    name: 'create_asset_upload',
    title: 'Upload file (by link)',
    description: 'Start uploading a file (image, PDF, etc.) to the wiki\'s file library. Returns a single-use link, valid 10 minutes, to send the raw file bytes to with HTTP PUT (e.g. curl -T). Missing folders are created. Use this for any real file; upload_asset is only for small generated text or tiny files.',
    scope: 'wiki:write',
    inputSchema: {
      type: 'object',
      properties: {
        path: str('Destination path including file name, e.g. "diagrams/network/flow.png". The name is lower-cased and spaces become underscores.', { maxLength: 255 }),
        overwrite: { type: 'boolean', description: 'Replace an existing file at this path for everyone (default false).' }
      },
      required: ['path']
    },
    async handler (args, ctx) {
      const plan = await assetOp(() => assets.planUpload(ctx.user, args.path, { overwrite: args.overwrite === true }))
      const token = await oauth.createFileToken({ grantId: ctx.grantId, kind: 'upload', scope: 'wiki:write', assetPath: plan.assetPath, overwrite: args.overwrite === true })
      const url = `${oauth.baseUrl()}/mcp/upload/${token}`
      return [
        `upload url (single use, valid ${oauth.UPLOAD_TTL / 60} minutes): ${url}`,
        `Send the raw file bytes as the request body with HTTP PUT, for example:`,
        `  curl -sSf -T ./local-file.${plan.filename.split('.').pop()} "${url}"`,
        `Do not use multipart/form-data (curl -F) or a JSON content type. Maximum size: ${formatSize(assets.maxFileSize())}.`,
        `The file will be stored at ${plan.assetPath}${plan.exists ? ', replacing the existing file' : ''}. The response is JSON and says whether it succeeded.`,
        `Once uploaded, reference it in Markdown as: ${assets.markdownFor(plan.assetPath)}`
      ].join('\n')
    }
  },
  {
    name: 'upload_asset',
    title: 'Upload small file',
    description: `Upload a small file (at most ${MAX_INLINE_UPLOAD / 1024} KB) by passing its content in the call: text (e.g. an SVG or CSV you wrote) or base64. Prefer create_asset_upload for existing files on disk. Missing folders are created.`,
    scope: 'wiki:write',
    inputSchema: {
      type: 'object',
      properties: {
        path: str('Destination path including file name, e.g. "diagrams/flow.svg".', { maxLength: 255 }),
        text: str('File content as UTF-8 text. Give either text or base64.'),
        base64: str('File content, base64 encoded. Give either text or base64.'),
        overwrite: { type: 'boolean', description: 'Replace an existing file at this path for everyone (default false).' }
      },
      required: ['path']
    },
    async handler (args, ctx) {
      if (_.isUndefined(args.text) === _.isUndefined(args.base64)) {
        throw new ToolError('Provide exactly one of text or base64.')
      }
      if (!_.isUndefined(args.base64) && !/^[A-Za-z0-9+/\s]*={0,2}\s*$/.test(args.base64)) {
        throw new ToolError('base64 is not valid base64.')
      }
      const data = _.isUndefined(args.text) ? Buffer.from(args.base64, 'base64') : Buffer.from(args.text, 'utf8')
      if (data.length > Math.min(MAX_INLINE_UPLOAD, assets.maxFileSize())) {
        throw new ToolError(`The file is larger than ${formatSize(Math.min(MAX_INLINE_UPLOAD, assets.maxFileSize()))}. Use create_asset_upload instead.`)
      }
      // Fail early, before writing anything
      await assetOp(() => assets.planUpload(ctx.user, args.path, { overwrite: args.overwrite === true }))
      const tmpPath = await assets.tempPath()
      await fs.writeFile(tmpPath, data)
      const stored = await assetOp(() => assets.store(ctx.user, args.path, tmpPath, { overwrite: args.overwrite === true }))
      return storedSummary(ctx, stored)
    }
  },
  {
    name: 'create_page',
    title: 'Create page',
    description: 'Create a new Markdown page. Fails if a page already exists at that path. Paths are lowercase-with-dashes segments separated by "/" and cannot contain spaces or dots.',
    scope: 'wiki:write',
    inputSchema: {
      type: 'object',
      properties: {
        path: PATH,
        locale: LOCALE,
        title: str('Page title.', { maxLength: 255 }),
        content: str('Page content in Markdown.'),
        description: str('Short one-line summary shown under the title.', { maxLength: 255 }),
        tags: { type: 'array', items: { type: 'string' }, description: 'Tags to set on the page.' },
        is_published: { type: 'boolean', description: 'Publish immediately (default true). Set false to save as an unpublished draft.' }
      },
      required: ['path', 'title', 'content']
    },
    async handler (args, ctx) {
      const locale = getLocale(args)
      const path = cleanPath(args.path)
      if (!can(ctx, ['write:pages'], { path, localeCode: locale })) {
        throw new ToolError(`You do not have permission to create a page at "${locale}/${path}".`)
      }
      let page
      try {
        page = await WIKI.models.pages.createPage({
          path,
          locale,
          title: args.title.trim(),
          description: args.description || '',
          content: args.content,
          editor: 'markdown',
          tags: args.tags || [],
          isPublished: args.is_published !== false,
          isPrivate: false,
          publishStartDate: '',
          publishEndDate: '',
          user: ctx.user
        })
      } catch (err) {
        throw new ToolError(err.message)
      }
      audit(ctx, 'created', `${page.localeCode}/${page.path}`)
      return savedSummary('Created', page)
    }
  },
  {
    name: 'update_page',
    title: 'Update page',
    description: 'Replace a page\'s content and/or change its title, description, tags or published state. Anything you omit is left unchanged. The previous version is kept in the page history. For small changes to a long page prefer edit_page.',
    scope: 'wiki:write',
    destructive: true,
    idempotent: true,
    inputSchema: {
      type: 'object',
      properties: {
        path: PATH,
        locale: LOCALE,
        content: str('New full content of the page, replacing the existing content.'),
        title: str('New title.', { maxLength: 255 }),
        description: str('New short description.', { maxLength: 255 }),
        tags: { type: 'array', items: { type: 'string' }, description: 'New complete list of tags, replacing the existing tags.' },
        is_published: { type: 'boolean', description: 'Publish or unpublish the page.' },
        expected_updated_at: str('The "updated" timestamp from read_page. If given, the update is refused when the page changed since.')
      },
      required: ['path']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      requirePermission(ctx, ['write:pages'], page, 'edit')
      checkNotStale(page, args.expected_updated_at)
      const changes = _.pickBy({
        content: args.content,
        title: args.title,
        description: args.description,
        tags: args.tags,
        isPublished: args.is_published
      }, v => !_.isUndefined(v))
      if (_.isEmpty(changes)) {
        throw new ToolError('Nothing to update: provide at least one of content, title, description, tags or is_published.')
      }
      const saved = await savePage(ctx, page, changes)
      audit(ctx, `updated (${_.keys(changes).join(', ')})`, `${saved.localeCode}/${saved.path}`)
      return savedSummary('Updated', saved)
    }
  },
  {
    name: 'edit_page',
    title: 'Edit page',
    description: 'Make targeted find-and-replace edits to a page\'s content without resending the whole page. Each old_text must match the current source exactly (including whitespace) and exactly once, unless replace_all is set. All edits are applied together or not at all.',
    scope: 'wiki:write',
    destructive: true,
    inputSchema: {
      type: 'object',
      properties: {
        path: PATH,
        locale: LOCALE,
        edits: {
          type: 'array',
          description: 'Edits to apply in order.',
          items: {
            type: 'object',
            properties: {
              old_text: str('Exact text to find.'),
              new_text: str('Text to replace it with (may be empty to delete).'),
              replace_all: { type: 'boolean', description: 'Replace every occurrence instead of requiring exactly one.' }
            },
            required: ['old_text', 'new_text']
          }
        },
        expected_updated_at: str('The "updated" timestamp from read_page. If given, the edit is refused when the page changed since.')
      },
      required: ['path', 'edits']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      requirePermission(ctx, ['write:pages'], page, 'edit')
      requirePermission(ctx, ['read:source'], page, 'view the source of')
      checkNotStale(page, args.expected_updated_at)
      if (args.edits.length < 1) {
        throw new ToolError('Provide at least one edit.')
      }
      let content = page.content
      args.edits.forEach((edit, idx) => {
        if (edit.old_text.length < 1) {
          throw new ToolError(`Edit ${idx + 1}: old_text cannot be empty.`)
        }
        const count = content.split(edit.old_text).length - 1
        if (count < 1) {
          throw new ToolError(`Edit ${idx + 1}: old_text was not found in the page. No changes were made.`)
        }
        if (count > 1 && !edit.replace_all) {
          throw new ToolError(`Edit ${idx + 1}: old_text matches ${count} places. Include more surrounding text or set replace_all. No changes were made.`)
        }
        content = content.split(edit.old_text).join(edit.new_text)
      })
      if (content === page.content) {
        throw new ToolError('The edits do not change the page.')
      }
      const saved = await savePage(ctx, page, { content })
      audit(ctx, `edited (${args.edits.length} edit(s))`, `${saved.localeCode}/${saved.path}`)
      return savedSummary('Edited', saved)
    }
  },
  {
    name: 'move_page',
    title: 'Move page',
    description: 'Move or rename a page to a new path. Links from other pages are updated. Fails if a page already exists at the destination.',
    scope: 'wiki:write',
    destructive: true,
    inputSchema: {
      type: 'object',
      properties: {
        path: PATH,
        locale: LOCALE,
        new_path: str('Destination path, without locale or leading slash.', { maxLength: 255 })
      },
      required: ['path', 'new_path']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      const destinationPath = cleanPath(args.new_path)
      if (!destinationPath || destinationPath === page.path) {
        throw new ToolError('new_path must be a different, non-empty path.')
      }
      try {
        await WIKI.models.pages.movePage({
          id: page.id,
          destinationPath,
          destinationLocale: page.localeCode,
          user: ctx.user
        })
      } catch (err) {
        throw new ToolError(err.message)
      }
      audit(ctx, 'moved', `${page.localeCode}/${page.path} to ${page.localeCode}/${destinationPath}`)
      return `Moved ${page.localeCode}/${page.path} to ${page.localeCode}/${destinationPath}\nurl: ${pageUrl({ localeCode: page.localeCode, path: destinationPath })}`
    }
  },
  {
    name: 'delete_page',
    title: 'Delete page',
    description: 'Delete a page. This removes it from the wiki for everyone; only an administrator can recover it afterwards. Always confirm with the user before calling this.',
    scope: 'wiki:write',
    destructive: true,
    inputSchema: {
      type: 'object',
      properties: {
        path: PATH,
        locale: LOCALE,
        confirm_title: str('The exact current title of the page, as a safeguard against deleting the wrong page.')
      },
      required: ['path', 'confirm_title']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      requirePermission(ctx, ['delete:pages'], page, 'delete')
      if (args.confirm_title !== page.title) {
        throw new ToolError(`confirm_title does not match the page title ("${page.title}"). Nothing was deleted.`)
      }
      try {
        await WIKI.models.pages.deletePage({ id: page.id, user: ctx.user })
      } catch (err) {
        throw new ToolError(err.message)
      }
      audit(ctx, 'deleted', `${page.localeCode}/${page.path}`)
      return `Deleted "${page.title}" (${page.localeCode}/${page.path}).`
    }
  },
  {
    name: 'restore_page_version',
    title: 'Restore page version',
    description: 'Roll a page back to a past version from get_page_history. The current content is kept in the history, so this can itself be undone.',
    scope: 'wiki:write',
    destructive: true,
    inputSchema: {
      type: 'object',
      properties: {
        path: PATH,
        locale: LOCALE,
        version_id: { type: 'integer', description: 'Version id from get_page_history.' }
      },
      required: ['path', 'version_id']
    },
    async handler (args, ctx) {
      const page = await loadPage(ctx, args)
      requirePermission(ctx, ['write:pages'], page, 'edit')
      requirePermission(ctx, ['read:history'], page, 'view the history of')
      const version = await WIKI.models.pageHistory.getVersion({ pageId: page.id, versionId: args.version_id })
      if (!version) {
        throw new ToolError(`Version ${args.version_id} does not exist for this page.`)
      }
      const saved = await savePage(ctx, page, {
        content: version.content,
        title: version.title,
        description: version.description
      })
      audit(ctx, `restored version ${args.version_id} of`, `${saved.localeCode}/${saved.path}`)
      return savedSummary(`Restored version ${args.version_id} of`, saved)
    }
  }
]

// ----------------------------------------
// Argument validation
// ----------------------------------------

/**
 * Validate a value against the small JSON Schema subset used by the tool definitions
 *
 * @returns {String|null} Error message, or null if valid
 */
const validate = (schema, value, name = 'arguments') => {
  switch (schema.type) {
    case 'object':
      if (!_.isPlainObject(value)) { return `${name} must be an object.` }
      for (const key of schema.required || []) {
        if (_.isNil(value[key])) { return `${name}: "${key}" is required.` }
      }
      for (const key of _.keys(value)) {
        if (!_.has(schema.properties, key)) { return `${name}: unknown property "${key}".` }
        if (_.isNil(value[key])) {
          delete value[key]
          continue
        }
        const err = validate(schema.properties[key], value[key], key)
        if (err) { return err }
      }
      return null
    case 'array':
      if (!_.isArray(value)) { return `"${name}" must be an array.` }
      if (value.length > 100) { return `"${name}" has too many items.` }
      for (let idx = 0; idx < value.length; idx++) {
        const err = validate(schema.items, value[idx], `${name}[${idx}]`)
        if (err) { return err }
      }
      return null
    case 'string':
      if (!_.isString(value)) { return `"${name}" must be a string.` }
      if (schema.maxLength && value.length > schema.maxLength) { return `"${name}" is longer than ${schema.maxLength} characters.` }
      if (schema.enum && !schema.enum.includes(value)) { return `"${name}" must be one of: ${schema.enum.join(', ')}.` }
      return null
    case 'integer':
      return _.isSafeInteger(value) ? null : `"${name}" must be an integer.`
    case 'boolean':
      return _.isBoolean(value) ? null : `"${name}" must be true or false.`
  }
  return null
}

module.exports = {
  ToolError,
  validate,
  tools,

  /**
   * Tool definitions visible to a connection with the given scopes
   */
  list (scopes) {
    return tools.filter(tool => scopes.includes(tool.scope)).map(tool => ({
      name: tool.name,
      title: tool.title,
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations: {
        title: tool.title,
        readOnlyHint: tool.readOnly === true,
        destructiveHint: tool.destructive === true,
        idempotentHint: tool.readOnly === true || tool.idempotent === true,
        openWorldHint: false
      }
    }))
  },

  /**
   * Run a tool. Returns an MCP tool result; expected failures are reported with isError.
   */
  async call (name, args, ctx) {
    const tool = _.find(tools, ['name', name])
    if (!tool || !ctx.scopes.includes(tool.scope)) {
      return null
    }
    const text = message => ({ content: [{ type: 'text', text: message }] })
    const input = _.cloneDeep(args || {})
    const invalid = validate(tool.inputSchema, input)
    if (invalid) {
      return { ...text(`Invalid input: ${invalid}`), isError: true }
    }
    try {
      const result = await tool.handler(input, ctx)
      return _.isString(result) ? text(result) : result
    } catch (err) {
      if (err instanceof ToolError) {
        return { ...text(err.message), isError: true }
      }
      WIKI.logger.warn(`MCP: tool ${name} failed for user ${ctx.user.id}: ${err.message}`)
      return { ...text('The wiki could not complete this request because of an internal error.'), isError: true }
    }
  }
}
