# Authentication Bridge Plugin: V1 testing alpha

This plugin adapts existing HTTP/HTTPS authentication to NHP without changing the
core protocol or message structs. It returns one short-lived, opaque exchange
code through the existing ACK `aspToken`. The app then exchanges that code over
HTTPS for its normal application login response. Application access/refresh
tokens and arbitrary login payloads are never forwarded in the ACK.

**Testing only: challenge/verifier binding is deliberately absent in V1. It must
be implemented and tested before any stable project tag is published.** Without
binding, a code is a bearer credential: possession plus access to the exchange
endpoint permits redemption. Expiry and single use do not replace binding.

**Use synthetic test credentials and tokens.** The unchanged core logs plaintext
packet bodies in debug and evaluation output. Evaluation logging is enabled at
`LogLevelError` and higher, so selecting Info instead of Debug does not prevent
this. Payload-log redaction must be resolved before real credentials are used
or a stable release is tagged. This plugin does not log backend bodies or
credential-bearing errors, but cannot suppress logging elsewhere in the stack.

## Build and configure

Run `make` in this directory, or `make plugins` at the repository root. The
server and plugin must use the same Go version, shared dependency versions and
build flags. The build installs the plugin and example configs under:

```text
release/nhp-server/plugins/auth-bridge/
```

Add this provider to the deployed server's `etc/resource.toml`:

```toml
["auth-bridge"]
PluginPath = "auth-bridge/auth-bridge.so"
```

Edit the plugin's `etc/config.toml` and `etc/resource.toml`. Replace the example
URLs, AC ID and destination address. Configure the AC's normal trusted-server
relationship and permit the NHP server's observed source address to reach the
backend authorization endpoints. Other clients stay blocked until the AC grants
access. The plugin does not configure these firewall rules or backend endpoints.

Use administrator ownership and service-account read access for configuration.
There is no remote edit or reload interface; restart the server after changes.
A build copies example configuration into the release directory, so manage your
deployed settings separately. Invalid initialization disables the plugin.

## Try login and renewal

Send knocks with `aspId = "auth-bridge"`, `resId = "existing-api"` and one
of these `usrData` objects:

Login:

```json
{"operation":"login","username":"person@example.com","password":"test-password"}
```

Renewal:

```json
{"operation":"renew","refresh_token":"synthetic-test-refresh-token"}
```

`operation` selects only a configured operation for this resource; it cannot
supply a URL, method, backend profile name or extra mappings. The example
defaults an omitted operation to `login`; delete `default_operation` to require
explicit selection. Empty, non-string and unconfigured operations are denied.
Login and renewal never fall back to one another after failure.

Both backend endpoints must return an authoritative resource authorization
result and an exchange code, for example:

```json
{
  "authorized": true,
  "code": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
  "expires_in": 30
}
```

The code above is an illustrative test fixture, not a production code generator.
The plugin validates the response before requesting AC access. On AC success,
`aspToken` contains only that code. The JS agent already exposes this field as
`accessToken`; in this integration, treat that value as an exchange code, not an
API bearer token. Your React Native wrapper should expose it with a clear name.

After the ACK and any required NHP pre-access steps, the app calls the protected
exchange endpoint directly:

```http
POST /nhp/exchange
Content-Type: application/json

{"code":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}
```

The backend validates and atomically consumes it, then returns the normal login
or renewal response directly to the app. The plugin does not call `/nhp/exchange`.
See [the migration guide](MIGRATION.md) for backend responsibilities and rollout.

## Configuration reference

`version = 1` identifies the config schema, not production readiness.

| Table | Purpose |
| --- | --- |
| `bindings.<resource>` | Optional `default_operation` |
| `bindings.<resource>.operations` | Allowed operation names mapped to backend profiles |
| `backends.<profile>` | Fixed request URL, method, encoding and runtime limits |
| `backends.<profile>.headers` | Administrator-controlled static headers |
| `backends.<profile>.fields` | Explicit input mappings, one array entry per field |
| `backends.<profile>.success` | Accepted statuses and optional JSON equality check |
| `backends.<profile>.code` | Code path, expiry path and bounded output limits |

Resource definitions follow the existing plugin convention in `resource.toml`.
Every resource needs a binding, positive `OpenTime`, `SkipAuth = false`, and
explicit AC, destination IP, port and TCP/UDP protocol. Multiple resources can
share a profile when that backend authorizes each resource appropriately. For
resource-specific static request values, use separate profiles.

Each field mapping specifies:

| Setting | Meaning |
| --- | --- |
| `source` | `userdata.<dot.path>`, `user_id`, `device_id`, or `organization_id` |
| `value` | Static value instead of `source`; exactly one is required |
| `target` | Destination field name; dot paths create nested JSON objects |
| `location` | `body`, `query`, or `header` |
| `type` | `string`, `number`, or `bool`, without coercion |
| `required` | Reject missing values and empty strings if true |
| `max_bytes` | Maximum string bytes or serialized scalar bytes; default 4096 |

Unmapped fields are ignored; optional missing fields are omitted. Null counts
as missing. JSON paths traverse objects, not arrays or names containing dots.
Objects/arrays cannot be forwarded wholesale; map scalar leaves explicitly.
Form and query targets are literal names (including names like `device[os]`),
and values are URL encoded. Header names are fixed; routing/framing headers and
static/dynamic header overlaps are rejected. Avoid credentials in query strings.

`encoding` supports `json`, `form`, or `none`. For example, a form-based backend
can map `userdata.username` to body field `user_name` without changing what the
app supplies in the knock. Backend URL, method and parameter names stay entirely
administrator-controlled. TLS verification is enabled, redirects are blocked,
and environment proxies are disabled. `allow_http = true` is for local tests
only. URL userinfo, fragments and inline query strings are rejected; configure
query values through mappings instead.

`success.statuses` must explicitly list accepted 2xx codes. If `path` and
`equals` are present, the JSON value must match too (`true` differs from
`"true"`). The backend must authorize the bound resource, not merely recognize
a user. Knock identity fields are client claims, not independently verified
identity. A static configured resource field is preferable to a client-selected
resource forwarded to the backend.

The `code` table requires `path` and `expires_in_path`. Codes must be strings
containing only ASCII base64url characters (`A-Z`, `a-z`, `0-9`, `_`, `-`),
32 through `max_bytes` characters long. The default maximum is 128, with a hard
configuration ceiling of 256. JSON envelopes and dotted JWTs are rejected.
`expires_in` must be a positive integer no greater than `max_ttl_seconds`
(default 30, hard ceiling 60). These checks validate the backend's declaration;
only the backend can enforce actual expiry, randomness and single use.

The whole backend response is read through a size limit before parsing. The
example uses 8192 bytes; the implementation default is 65536. Requests have a
3-second default timeout and a per-profile concurrency cap of 32, not a per-user
rate limit. Failed requests return generic denial without upstream response
bodies. There are no automatic application retries. Connection shutdown or
plugin close cancels pending HTTP requests.

A short code reduces ACK size but does not remove the core's 4096-byte packet
limit. Other ACK metadata still consumes space. Likewise, large refresh tokens
must fit the incoming knock budget. Test actual tokens, resource groups, SDKs
and cipher schemes before deployment. Failed AC operations withhold the code;
any code already issued expires on the backend. Full packet delivery and
backend exchange remain separate steps, not a distributed transaction.

Registration, OTP, service discovery and inbound HTTP login handlers are not
implemented by this plugin. Provision agent identities using the existing
server mechanisms. This is a single-request adapter, not an OAuth browser,
redirect, MFA or consent-flow engine.

## Verification

```sh
go test -race ./...
go vet ./...
```

Tests use local mock HTTP/TLS servers and never contact the example domain.
They cover mappings, operation routing, strict config, code/expiry limits,
backend denial, TLS, redirects, timeout, concurrency, shutdown and AC failure.
