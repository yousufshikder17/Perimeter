# Reviewed logout/session replay

The engine supports fresh session-cookie handles for opt-in mutating probes.
Each handle can only read its reviewed GET and POST its reviewed logout. It does
not expose a cookie, accept URL overrides, adopt Set-Cookie changes, or refresh
credentials. Generic HTTP probes gain no logout/write exception.

Use a dedicated disposable test account and a current-session-only logout route.
Never point this at an operator's existing session or an account-wide logout.
The explicit acknowledgements are operator-reviewed contracts, not properties
the scanner can establish automatically. Login and logout may affect other
sessions on single-session-per-account services; keep this account out of use.

```yaml
auth:
  scheme: session_cookie
  tokenEndpoint: /login
  login: { format: json, cookieName: session }
identities:
  - ref: disposable
    tenant: tenant-a
    credentials: { env: PERIMETER_SESSION_TEST }
endpoints:
  - { id: logout, method: POST, path: /logout, auth: required }
  - id: profile
    method: GET
    path: /profile
    auth: required
    sessionReplay:
      readOnly: true
      disposableIdentity: true
      currentSessionOnly: true
      identity: disposable
      resultPath: [id]
      expectedValue: disposable-test-user-id
      logoutEndpointId: logout
      logoutBody: {}
      logoutSuccessStatus: 204
```

Merge this into a complete target model with tenancy and authorization metadata.
The credential environment variable contains a JSON object of login fields,
such as username/password; do not put secrets in the model. The selected response
scalar must be non-secret, distinguishing data available only to that account.
Login, protected GET, and logout must be separate same-origin URLs. Logout is a
literal POST with a bounded static JSON body and a reviewed 200/204 success status.
Dynamic CSRF challenges, browser flows, pre-issued cookies, bearer/refresh tokens,
account-wide revocation, session fixation, and delayed revocation are not covered.

All traffic shares the scan/probe budgets, rate limits, cancellation and audit.
Login bodies are never captured; cookie headers and known cookie echoes are
redacted. Reads require complete unmodified captured JSON for conclusions.
Fresh logins returning the same cookie are inconclusive.

The engine attempts logout once per session, including on probe failure, then
invalidates the shared identity cache. Cleanup still obeys cancellation and
budgets; interrupted login, failed logout or a vulnerable server may leave a
test session active. Operators must clean up the disposable account afterward.
Clearing a browser cookie is not proof of server-side revocation.
