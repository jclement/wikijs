/* global WIKI */

exports.up = knex => {
  const dbCompat = {
    charset: (WIKI.config.db.type === `mysql` || WIKI.config.db.type === `mariadb`)
  }
  return knex.schema
    // MCP OAUTH CLIENTS -------------------
    .createTable('mcpClients', table => {
      if (dbCompat.charset) { table.charset('utf8mb4') }
      table.string('id', 64).primary()
      table.string('name').notNullable()
      table.text('redirectUris').notNullable()
      table.string('createdAt').notNullable()
    })
    // MCP OAUTH GRANTS --------------------
    .createTable('mcpGrants', table => {
      if (dbCompat.charset) { table.charset('utf8mb4') }
      table.increments('id').primary()
      table.string('clientId', 64).notNullable().references('id').inTable('mcpClients').onDelete('CASCADE')
      table.integer('userId').unsigned().notNullable().references('id').inTable('users').onDelete('CASCADE')
      table.string('scope').notNullable()
      table.string('createdAt').notNullable()
      table.string('lastUsedAt').notNullable()
    })
    // MCP OAUTH TOKENS --------------------
    .createTable('mcpTokens', table => {
      if (dbCompat.charset) { table.charset('utf8mb4') }
      table.increments('id').primary()
      table.integer('grantId').unsigned().notNullable().references('id').inTable('mcpGrants').onDelete('CASCADE')
      table.string('kind', 10).notNullable()
      table.string('hash', 64).notNullable().unique()
      table.string('expiresAt').notNullable()
      table.string('usedAt')
      table.text('meta')
    })
}

exports.down = knex => { }
