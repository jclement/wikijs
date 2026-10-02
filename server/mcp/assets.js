const _ = require('lodash')
const crypto = require('crypto')
const fs = require('fs-extra')
const path = require('path')
const sanitize = require('sanitize-filename')
const pageHelper = require('../helpers/page')

/* global WIKI */

// Asset (file / image) access for the MCP tools. Assets are addressed by the path they are
// served at, e.g. "diagrams/network/flow.png", and every operation is checked against the
// same read:assets / write:assets page rules as the web UI.

const MAX_DEPTH = 8
const OWN_PATHS = ['mcp', 'oauth', '.well-known']

// Types the stored mime type is derived from: the extension decides, never the uploader
const MIME_TYPES = {
  png: 'image/png',
  apng: 'image/apng',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  bmp: 'image/bmp',
  svg: 'image/svg+xml',
  ico: 'image/x-icon',
  pdf: 'application/pdf',
  txt: 'text/plain',
  log: 'text/plain',
  csv: 'text/csv',
  tsv: 'text/tab-separated-values',
  json: 'application/json',
  xml: 'application/xml',
  yml: 'text/yaml',
  yaml: 'text/yaml',
  zip: 'application/zip',
  gz: 'application/gzip',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  mp3: 'audio/mpeg',
  mp4: 'video/mp4',
  webm: 'video/webm'
}

// What an assistant can be shown directly
const INLINE_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp']
const TEXT_EXTENSIONS = ['txt', 'log', 'csv', 'tsv', 'json', 'xml', 'yml', 'yaml', 'svg', 'ini', 'conf', 'sql', 'drawio']

class AssetError extends Error {
  constructor (message, status = 400) {
    super(message)
    this.status = status
  }
}

const cleanPath = value => _.trim(_.toString(value).trim(), '/')

const extOf = filename => path.extname(filename).slice(1).toLowerCase()

/**
 * The wiki serves assets with the locale parsed from the URL (the main locale for asset
 * paths), while its uploader and asset list check the bare path. Locale-specific rules
 * apply to one and not the other, so access requires both.
 */
const can = (user, permissions, assetPath) =>
  WIKI.auth.checkAccess(user, permissions, { path: assetPath }) &&
  WIKI.auth.checkAccess(user, permissions, { path: assetPath, locale: WIKI.config.lang.code })

// Names are compared exactly here: with a case-insensitive database collation, "SECRET.PNG"
// would otherwise find "secret.png" after access was checked for the other spelling.
// Duplicate folders (the schema allows them) always resolve to the oldest one.
const findFolder = async (parentId, slug) => {
  const query = WIKI.models.knex('assetFolders').where('slug', slug).orderBy('id')
  const rows = await (_.isNil(parentId) ? query.whereNull('parentId') : query.where('parentId', parentId))
  return _.find(rows, ['slug', slug])
}

const findFile = async (folderId, filename) => {
  const query = WIKI.models.knex('assets').where('filename', filename).orderBy('id')
  const rows = await (_.isNil(folderId) ? query.whereNull('folderId') : query.where('folderId', folderId))
  return _.find(rows, ['filename', filename])
}

/**
 * Walk a list of folder slugs from the root.
 *
 * @returns {Promise<Number|null|undefined>} Folder id, null for the root, undefined if a folder is missing
 */
const resolveFolder = async slugs => {
  let folderId = null
  for (const slug of slugs) {
    const folder = await findFolder(folderId, slug)
    if (!folder) { return undefined }
    folderId = folder.id
  }
  return folderId
}

// Uploads are stored one at a time, so that "does it exist yet" and "create folder" checks
// cannot interleave with another upload in this process
let storeQueue = Promise.resolve()
const serialized = fn => {
  const run = storeQueue.then(fn, fn)
  storeQueue = run.catch(() => {})
  return run
}

module.exports = {
  AssetError,
  INLINE_IMAGE_TYPES,
  cleanPath,
  can,

  mimeOf (filename) {
    return MIME_TYPES[extOf(filename)] || 'application/octet-stream'
  },

  /**
   * How to reference an asset from a Markdown page
   */
  markdownFor (assetPath) {
    return [...INLINE_IMAGE_TYPES, 'image/svg+xml'].includes(this.mimeOf(assetPath)) ?
      `![description](/${assetPath})` :
      `[${assetPath.split('/').pop()}](/${assetPath})`
  },

  isText (filename) {
    return TEXT_EXTENSIONS.includes(extOf(filename))
  },

  maxFileSize () {
    return _.toSafeInteger(_.get(WIKI.config, 'uploads.maxFileSize')) || 5242880
  },

  /**
   * Find an asset by the path it is served at
   *
   * @returns {Promise<Object|null>} Asset row with its path, or null
   */
  async find (assetPath) {
    const parts = cleanPath(assetPath).split('/')
    const filename = parts.pop()
    if (!filename) { return null }
    const folderId = await resolveFolder(parts)
    if (_.isUndefined(folderId)) { return null }
    const asset = await findFile(folderId, filename)
    return asset ? { ...asset, path: [...parts, filename].join('/') } : null
  },

  /**
   * Find an asset the user may read. Missing and inaccessible assets are indistinguishable on purpose.
   */
  async findReadable (user, rawPath) {
    const assetPath = cleanPath(rawPath)
    const asset = assetPath && can(user, ['read:assets'], assetPath) ? await this.find(assetPath) : null
    if (!asset) {
      throw new AssetError(`No file at "${assetPath}", or you do not have access to it.`, 404)
    }
    return asset
  },

  /**
   * Folders and files directly inside a folder, limited to what the user may read
   */
  async list (user, rawPath) {
    const folderPath = cleanPath(rawPath || '')
    const folderId = await resolveFolder(folderPath ? folderPath.split('/') : [])
    if (_.isUndefined(folderId) || (folderPath && !can(user, ['read:assets'], folderPath))) {
      throw new AssetError(`No folder at "${folderPath}", or you do not have access to it.`, 404)
    }
    const within = name => folderPath ? `${folderPath}/${name}` : name
    const folders = await (_.isNil(folderId) ? WIKI.models.knex('assetFolders').whereNull('parentId') : WIKI.models.knex('assetFolders').where('parentId', folderId)).orderBy('slug')
    const files = await (_.isNil(folderId) ? WIKI.models.knex('assets').whereNull('folderId') : WIKI.models.knex('assets').where('folderId', folderId)).orderBy('filename')
    return {
      path: folderPath,
      folders: folders.map(f => within(f.slug)).filter(p => can(user, ['read:assets'], p)),
      files: files.map(f => ({ ...f, path: within(f.filename) })).filter(f => can(user, ['read:assets'], f.path))
    }
  },

  async readData (asset) {
    const row = await WIKI.models.knex('assetData').where('id', asset.id).first()
    if (!row || _.isNil(row.data)) {
      throw new AssetError(`The contents of "${asset.path}" are not available.`, 404)
    }
    return Buffer.isBuffer(row.data) ? row.data : Buffer.from(row.data)
  },

  /**
   * Validate where a user wants to put a file, applying the same filename clean-up as the web uploader
   *
   * @returns {Promise<Object>} { assetPath, folders, filename, exists }
   */
  async planUpload (user, rawPath, { overwrite = false } = {}) {
    const parts = cleanPath(rawPath).split('/').map(p => p.trim())
    const filename = sanitize(parts.pop().toLowerCase().replace(/[\s,;#]+/g, '_'))
    const folders = parts.map(p => p.toLowerCase())
    const assetPath = [...folders, filename].join('/')

    if (!/^[\p{L}\p{N}_][\p{L}\p{N}._-]*\.[a-z0-9]{1,10}$/u.test(filename) || filename.includes('..')) {
      throw new AssetError('The file name must have an extension and may only contain letters, digits, dots, dashes and underscores, e.g. "network-diagram.png".')
    }
    if (_.some(_.castArray(WIKI.config.pageExtensions || []), ext => filename.endsWith(`.${ext}`))) {
      throw new AssetError(`Files ending in .${extOf(filename)} are treated as wiki pages and cannot be uploaded as files.`)
    }
    if (folders.length > MAX_DEPTH || assetPath.length > 255) {
      throw new AssetError('The path is too long or too deeply nested.')
    }
    if (!folders.every(slug => /^[\p{L}\p{N}_][\p{L}\p{N}_-]*$/u.test(slug))) {
      throw new AssetError('Folder names may only contain letters, digits, dashes and underscores.')
    }
    // The first path segment decides whether the wiki can serve the file at all
    if (pageHelper.isReservedPath(assetPath) || OWN_PATHS.includes(assetPath.split('/')[0])) {
      throw new AssetError(`"${assetPath.split('/')[0]}" is reserved by the wiki. Put the file in a differently named folder.`)
    }
    if (!can(user, ['write:assets'], assetPath)) {
      throw new AssetError(`You do not have permission to upload files to "${assetPath}".`, 403)
    }

    const folderId = await resolveFolder(folders)
    const existing = _.isUndefined(folderId) ? null : await findFile(folderId, filename)
    if (existing && !overwrite) {
      throw new AssetError(`A file already exists at "${assetPath}". Choose another name, or set overwrite to replace it for everyone.`, 409)
    }
    return { assetPath, folders, filename, exists: Boolean(existing) }
  },

  /**
   * Path for a file being received, inside the wiki's temporary uploads folder
   */
  async tempPath () {
    const dir = path.resolve(WIKI.ROOTPATH, WIKI.config.dataPath, 'uploads')
    await fs.ensureDir(dir)
    return path.join(dir, `mcp-${crypto.randomBytes(16).toString('hex')}`)
  },

  /**
   * Store a received file as an asset, creating missing folders. The temporary file is always removed.
   *
   * @returns {Promise<Object>} { path, size, replaced }
   */
  async store (user, rawPath, tmpPath, { overwrite = false } = {}) {
    try {
      const { size } = await fs.stat(tmpPath)
      if (size < 1) {
        throw new AssetError('The file is empty.')
      }
      if (size > this.maxFileSize()) {
        throw new AssetError(`The file is larger than the ${this.maxFileSize()} byte limit of this wiki.`, 413)
      }
      return await serialized(async () => {
        // Checked again here: permissions or the destination may have changed since the upload was planned
        const plan = await this.planUpload(user, rawPath, { overwrite })

        let folderId = null
        for (const slug of plan.folders) {
          let folder = await findFolder(folderId, slug)
          if (!folder) {
            await WIKI.models.knex('assetFolders').insert({ slug, name: slug, parentId: folderId })
            folder = await findFolder(folderId, slug)
          }
          folderId = folder.id
        }

        await WIKI.models.assets.upload({
          originalname: plan.filename,
          mimetype: this.mimeOf(plan.filename),
          size,
          path: tmpPath,
          mode: 'upload',
          folderId,
          assetPath: plan.assetPath,
          user
        })
        // The asset model logs storage failures instead of raising them. It moves the
        // temporary file away only once the data is saved, so a leftover file means it failed.
        if (await fs.pathExists(tmpPath) || !(await findFile(folderId, plan.filename))) {
          throw new Error(`asset model did not store ${plan.assetPath}`)
        }
        return { path: plan.assetPath, size, replaced: plan.exists }
      })
    } finally {
      await fs.remove(tmpPath).catch(() => {})
    }
  }
}
