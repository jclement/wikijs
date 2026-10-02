# MCP server

Lets users connect an AI assistant (Claude Desktop, claude.ai, Claude Code, or any
other MCP client) to the wiki. The assistant acts **as the user who connected it**
and can never do more than that user can.

## Enabling

1. Set the **Site URL** in Administration > General (it must be the public `https://` URL).
2. Set `mcp.enabled: true` in `config.yml`, or `MCP_ENABLED=true` when using the Docker image.
3. In Claude: Settings > Connectors > Add custom connector, and enter `https://<your wiki>/mcp`.
   With Claude Code: `claude mcp add --transport http wiki https://<your wiki>/mcp`.

When enabled, the paths `/mcp`, `/oauth/*` and `/.well-known/oauth-*` are reserved and
cannot be used as wiki page paths.

Users can review and disconnect their applications at `/oauth/connections`.

## How access is controlled

- **Sign-in** goes through the wiki's normal login page, so SSO and 2FA apply. The user
  then sees a consent screen naming the application and where it will be sent, and can
  untick write access to make the connection read-only.
- **OAuth 2.1**: authorization code flow with mandatory PKCE (S256), public clients only,
  dynamic client registration (RFC 7591) with redirect URIs restricted to https, loopback
  and app-specific schemes, and exact redirect URI matching.
- **Tokens** are opaque random values stored only as SHA-256 hashes. Access tokens last one
  hour. Refresh tokens last 30 days, are rotated on every use, and reuse of an old one
  revokes the whole connection.
- **Every request** reloads the user and their groups, so deactivating a user or changing
  group permissions takes effect immediately.
- **Every tool** goes through the same `WIKI.auth.checkAccess` page rules and page model
  checks as the web UI. Pages the user cannot read are reported exactly like pages that do
  not exist.
- **No administration**: there are no tools for users, groups, settings, storage, assets or
  comments, and page scripts / styles cannot be set through MCP (existing ones are kept).
- The `/mcp` endpoint only accepts bearer tokens issued here, never the browser session
  cookie or wiki API keys.
- Changes made through MCP are logged (`MCP: user <id> via "<application>" ...`) and are
  recorded in the page history under the user's name like any other edit.

## Tools

| Tool | Scope | What it does |
| --- | --- | --- |
| `whoami` | read | Connected user, scopes and locales |
| `search_pages` | read | Full-text search |
| `list_pages` | read | List pages by path prefix / tags |
| `browse_tree` | read | Folder-style listing of one level |
| `read_page` | read | Page metadata and source |
| `get_page_history` | read | Past versions of a page |
| `get_page_version` | read | Content of a past version |
| `list_tags` | read | Tags in use |
| `create_page` | write | Create a Markdown page |
| `update_page` | write | Replace content and/or metadata |
| `edit_page` | write | Exact find-and-replace edits |
| `move_page` | write | Move / rename a page |
| `delete_page` | write | Delete a page (requires the exact title) |
| `restore_page_version` | write | Roll back to a past version |

`update_page` and `edit_page` accept `expected_updated_at` (from `read_page`) and refuse
to save if the page changed in the meantime.

## Layout

- `oauth.js` - authorization server logic and token storage
- `rpc.js` - JSON-RPC / MCP protocol handling (stateless Streamable HTTP)
- `tools.js` - tool definitions
- `../controllers/mcp.js` - HTTP routes
- `../views/mcp/` - consent and connected-applications pages
- `../db/migrations*/2.5.129.js` - `mcpClients`, `mcpGrants`, `mcpTokens` tables
