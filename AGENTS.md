# osvc-auth-mcp: context for coding agents

Shared Go library of the OpenSVC MCP servers, `om3-mcp` and `oc3-mcp`: OAuth
verification of the incoming MCP access tokens and RFC 8693 exchange for the
token of the target. Module `github.com/opensvc/osvc-auth-mcp`; no binary.
Use Go, the standard library, `github.com/golang-jwt/jwt/v5` and
`go.yaml.in/yaml/v2`.

## Rules

- Stay generic: no OpenSVC daemon, cluster or collector concept. A target is
  an audience and an opaque value chosen by the MCP server; headers specific
  to a server are passed to `Middleware` by that server.
- An MCP access token never reaches a target, and an exchanged token is never
  usable as an MCP token. Exchanged tokens live only in the in-memory cache
  (`exchange_cache.go`): at most one minute, keyed by a hash, failures never
  cached. Never log, return or otherwise store tokens or secrets, and
  never quote them, or SSO error descriptions, in errors.
- Discovery, JWKS and token requests use HTTPS, no proxy or redirect, bounded
  reads and no caller credentials.
- Both MCP servers depend on this API: change it compatibly, or update both in
  the same release. Tag a release (semantic versioning) for every change used
  by an MCP server.
- Test with the fakes of `mcpauthtest`, without network access, and keep the
  CI green: gofmt, `go mod tidy -diff`, vet, staticcheck v0.7.0,
  `go test -race`.
