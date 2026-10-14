# osvc-auth-mcp

Shared OAuth resource-server and RFC 8693 token-exchange library for the
OpenSVC MCP servers, [om3-mcp](https://github.com/opensvc/om3-mcp) and
[oc3-mcp](https://github.com/opensvc/oc3-mcp).

An MCP server serves external clients over HTTPS. Their OAuth access tokens are
intended for the MCP and never reach its target. Each tool call exchanges them
for a token intended for the target (an OpenSVC cluster daemon or the
collector), which verifies it independently.

## Packages

- `mcpauth`
  - `OAuthVerifier`: verifies the access JWTs of the MCP resource locally
    (issuer JWKS, issuer, audience = the resource URL, dates), serves the
    RFC 9728 resource metadata and the 401 challenge. `Middleware` removes the
    `Authorization` header and the headers its caller names.
  - `ExchangeProfiles`: the confidential exchange clients loaded from
    `auth.yaml`. `Prepare` provides the token of one tool call for a target
    audience; `ExchangedFromContext` returns it to the transport of the
    target, with the opaque target value given to `Prepare`, and
    `ForgetExchanged` drops it when the target refuses it (HTTP 401 or 403).
  - `CallLimiter`: calls in progress and calls per minute of each identity.
  - `CallTrace`: credential-free audit facts of a tool call.
  - `ValidClaimText`, `OpenIDSigningMethod`, `MaxTokenBytes`: the token checks
    shared with the delegated tokens of the MCP servers.
- `mcpauthtest`: fake OAuth provider, HTTPS server and exchange profiles for
  the tests of the MCP servers.

## Exchange profiles

```yaml
version: 1
profiles:
  customer-sso:
    issuer: https://sso.example.com/application/o/mcp-exchange/
    client_id: mcp-exchange
    client_secret_file: /etc/opensvc-mcp/secrets/mcp-exchange
    token_endpoint_auth_method: client_secret_basic
    scopes: [openid, profile]
    request_timeout: 10s
```

The secret file must not be readable by group or others (`0600` or `0400`).
The scopes are those of the target provider: request the scope that carries
the claims the target authorizes.

## Exchange cache

An exchanged token is kept in the memory of the MCP process, never on disk,
and reused by the next tool calls of the same MCP token for the same target:
for at most one minute, and never within 30 seconds of its expiry. The cache
key is a hash of the MCP token and the target, never the MCP token itself.
Concurrent calls share one exchange. A failed exchange is returned again for
five seconds without contacting the SSO, so that a client looping on a refused
token makes at most one SSO request per period. When the target refuses the
token (HTTP 401 or 403), it is forgotten and the next call exchanges again. A
claim change in the SSO therefore applies within a minute.

## Call limits

`CallLimiter` bounds the tool calls of each authenticated identity (issuer and
subject): `DefaultMaxConcurrentCalls` (10) calls in progress, and
`DefaultMaxCallsPerMinute` (120) calls per minute with a burst of 30 for an
idle identity; 0 disables a limit. A refused call fails at once, without
queueing, with an error that wraps `ErrCallLimited` and tells the client when
to retry. It protects the SSO and the targets from an authenticated client that
loops. Limits per IP address, before authentication or for all identities
belong to the network infrastructure in front of the MCP servers: behind a
reverse proxy, every request carries the address of the proxy.

## Development

```bash
gofmt -l .
go mod verify && go mod tidy -diff
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go test -race -count=1 ./...
```

An MCP server tests a local change of this module with a `replace` directive
pointing to its checkout, never committed. A change is released with a tag,
then each MCP server updates its `go.mod`.
