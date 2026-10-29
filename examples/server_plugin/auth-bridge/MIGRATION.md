# V1 migration: application login and renewal through NHP

This alpha uses existing NHP `usrData` and `aspToken`; it requires no core schema
changes. Full application responses remain on HTTPS. Use synthetic credentials
and tokens for testing because unchanged core packet logs may contain secrets.

## Required before a stable project tag

**Do not publish a stable project tag until challenge/verifier binding is
implemented and verified end to end for both login and renewal.** V1 testing
intentionally omits it. A short lifetime, encrypted knock, source-IP firewall
rule and single use are not substitutes for binding a code to its initiating
app. Evaluate S256 PKCE-style binding for the next iteration; this custom flow
is not automatically a compliant OAuth authorization-code grant.

Before stable release, also resolve plaintext packet logging and test actual
mobile delivery, expiry, concurrent redemption, refresh rotation and revocation
with the deployed backend and AC. The tests in this plugin do not implement or
certify your backend's code store or exchange semantics.

## Preserve the existing login API

Keep `/oauth/login` and its response unchanged. Add small backend adapters that
reuse your existing authentication, authorization and token/session issuance
services. Example routes:

| Endpoint | Caller | Responsibility |
| --- | --- | --- |
| `/nhp/authorize` | NHP plugin | Validate login, authorize resource, prepare login exchange code |
| `/nhp/renew` | NHP plugin | Validate refresh/session proof, recheck entitlement, prepare renewal exchange code |
| `/nhp/exchange` | App after access opens | Validate/consume code and return normal login or renewal response |

These routes are an example, not mandatory names. One existing endpoint can
support explicit request modes if doing so preserves its normal behavior, or
an existing exchange endpoint may already satisfy the contract. The plugin
maps each allowed operation to a fixed configured request. It does not add
these endpoints to your application or require users to replace their IAM.

The NHP server needs its restricted, permanent path to the authorization and
renewal endpoints on the protected backend. Firewall rules on IP/port cannot
restrict individual HTTPS paths; application middleware or a reverse proxy
must enforce path restrictions where needed. Authenticate this server-to-server
path as appropriate, for example with a configured service credential and TLS.
The exchange endpoint must be reachable by the app after the AC opens access.

## Login

1. App sends an encrypted knock with `usrData.operation = "login"` and its
   existing login inputs. Configure field mappings to retain existing names
   and backend parameter formats.
2. `/nhp/authorize` authenticates and authorizes access to the configured
   resource. It stores a short-lived pending login record and returns a code.
3. Plugin checks success, code format/size, and declared lifetime before the
   server requests AC access.
4. On AC success the ACK returns the code in `aspToken`.
5. App completes any required NHP pre-access steps, then posts the code directly
   to `/nhp/exchange` over HTTPS.
6. Backend validates and consumes the code, then issues the normal application
   session/tokens. Existing client response handling can be reused.

For example, V1 backend authorization responses use:

```json
{"authorized":true,"code":"<random-base64url-code>","expires_in":30}
```

The exchange response can retain the application's existing JSON structure or
cookie/session behavior. For cookie-based systems, the mobile HTTP client must
retain cookies from the direct exchange response. The plugin cannot transfer
cookies created by its own backend requests into the app's cookie jar.

## Renewal

Network access windows and application token lifetimes are independent. A
closed AC window must not force a password prompt while a valid application
session still exists.

1. App sends `usrData.operation = "renew"` with its refresh token.
2. `/nhp/renew` verifies validity, revocation, client/session association and
   permission for the resource. It creates a pending renewal code without
   consuming or rotating the refresh token at this step.
3. Plugin obtains AC access and returns the code via `aspToken`.
4. App exchanges it directly over HTTPS.
5. Backend revalidates session state and atomically performs redemption and
   refresh-token rotation, following its existing refresh/replay policy. The
   app securely replaces its tokens with the direct exchange result.

Code records must remember whether they represent login or renewal; the app
must not be able to turn one kind into the other at redemption. Concurrent
renewals must not allow the same refresh token to rotate independently twice.
Serializing renewal in the app helps, but backend enforcement is required.
Never silently fall back to login or grant access when renewal is denied.
Expired/revoked sessions require normal reauthentication.

Later, a separate configured operation could validate an unexpired access token
just to reopen network access, avoiding unnecessary refresh rotation. V1's
example defines login and refresh-based renewal only.

## Backend code contract

- Generate opaque codes using a cryptographically secure random generator;
  32 random bytes encoded as unpadded base64url produces a 43-character code.
  Code length validation in the plugin does not prove entropy.
- Store a hash of the code with server-side identity, authorized resource,
  operation, application/client context, expiry and pending session state.
  Do not trust a claimed user ID or device ID as proof of identity.
- Start expiry when issued. A 30-second lifetime is the test default; AC and
  mobile latency consume that window. The plugin accepts at most 60 seconds.
- Validate context and expiry before atomically consuming the code. Enforce
  single use and recheck revocation/entitlement at redemption.
- Issue application tokens at successful exchange. For renewal, coordinate
  code consumption, session validation and rotation transactionally.
- Return generic errors; never put credentials or codes into URLs or logs.
  Apply application rate limits and secure token storage.

Client IDs and other declared metadata do not provide cryptographic sender
binding. V1 codes remain bearer credentials until challenge binding is added.

## Failure and retry behavior

| Failure | Expected behavior |
| --- | --- |
| Bad credentials, revoked session, denied resource | No AC request; no code returned to app |
| Missing/oversized code or invalid lifetime | No AC request; backend code expires unused |
| Backend error, timeout, redirect, malformed response | Generic denial; no AC request |
| AC failure | Code withheld; backend code expires; refresh token remains valid |
| Lost ACK | App may repeat knock; backend bounds pending codes; do not rotate refresh token yet |
| Code expired or already redeemed | Exchange rejects it; app starts a fresh authorization attempt |
| Lost exchange response after refresh rotation | Follow an explicit backend recovery policy; blind reuse can trigger replay detection |
| Mobile address changes before exchange | Re-knock from the new network; do not rely on IP alone to bind codes |

The exchange step still has ordinary HTTPS/token-refresh failure modes. Define
idempotent recovery bound to the initiating client before production, or use a
clear reauthentication path. Never enable unlimited replay to recover a lost
response. Access rules already granted by the AC expire under the existing AC
policy even if the app never redeems the code.

## Rollout checklist

1. Inventory current login inputs/results, MFA, refresh and revocation behavior.
   Multi-step MFA needs application-specific orchestration beyond this adapter.
2. Add and test the backend adapters without changing `/oauth/login` behavior.
3. Configure plugin mappings and resource-specific authorization checks. Verify
   denied requests never trigger AC operations.
4. Update the app to knock, read `aspToken`, finish pre-access, exchange the code,
   and pass the result into existing login handling. Add serialized renewal.
5. Test actual device networks, retries, expiry, code reuse, rotation, logout,
   revocation and failures between each step, using test accounts and tokens.
6. Define the legacy-client cutover. Preserving `/oauth/login`'s schema does not
   let old clients reach port 443 once NHP blocking is enforced.
7. Before any stable tag, implement/test challenge binding and resolve core
   payload logging. Then validate the full flow with real deployment limits.
