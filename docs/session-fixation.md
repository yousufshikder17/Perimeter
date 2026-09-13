# Reviewed session fixation

The engine can retain a freshly issued anonymous cookie while logging a dedicated
disposable account in through the existing JSON/form login contract. Only that
owned cookie and the resulting authenticated cookie are used. No victim account,
stolen/pre-issued cookie, browser injection or guessed session identifier is involved.

Reuse the identity, protected marker and current-session logout contract from
[session replay](session-replay.md), then add a reviewed anonymous session issuer:

~~~yaml
# Add to endpoints:
- { id: anonymous-session, method: GET, path: /login, auth: none }

# Add under the protected GET's existing sessionReplay annotation:
fixation:
  bootstrapEndpointId: anonymous-session
  issuesAnonymousSession: true
~~~

The issuer must be a literal same-origin GET, separate from the protected GET
and logout. It may share the login POST's path. It must return 200 and exactly
one live cookie with the configured login cookie name. Redirects, duplicate,
empty, expired and missing cookies are rejected. Set-Cookie headers and known
cookie echoes are redacted; bootstrap and login bodies are never captured.

Fixation handles expose only the reviewed read, a single memoized login, and
cleanup. Login sends the original anonymous cookie; if the server omits a new
cookie, the original is retained. A deleted/invalid cookie is never treated as
an omitted cookie. Generic HTTP probes receive no new write permission.
Reads that change/delete the selected cookie are inconclusive, so a read-induced
rotation cannot be misattributed to login.
Known anonymous-cookie expiry during the check is also inconclusive, not a pass.

All operations require mutating opt-in and share the scan's guarded HTTP,
request budgets, rate limits, audit and cancellation. Both owned cookies are
logged out when possible; 401/403 is an acceptable cleanup response for a revoked
anonymous cookie. Failed/interrupted login may leave an unknown server session;
operator cleanup remains necessary for failures or vulnerable targets.

This checks a server-side prerequisite for [session fixation](https://owasp.org/www-community/attacks/Session_fixation),
not how an attacker could plant a cookie in someone else's browser. Cookie
domain/path rules, browser/MFA/dynamic-CSRF flows, URL/form session IDs,
privilege-elevation transitions and refresh-token replay are outside this profile.

## Standard probe

Set the scan config's include list to [auth/session-fixation] and run:

~~~sh
perimeter scan --config scan.yaml --allow-mutating
~~~

Without write opt-in the probe is skipped before bootstrap/login. It cannot use
checkpoint/resume. Up to nine requests are reserved per endpoint: anonymous
read, bootstrap, pre-login read, login, authenticated read, original-cookie replay,
authenticated recheck and two cleanup logouts (one if the cookie was retained).
The per-probe ceiling is 45. Cleanup settles before the next endpoint starts.

A finding requires the exact pre-login cookie to expose the expected account
marker only after authentication, with both authenticated controls succeeding.
Unchanged cookie bytes alone are not a finding. Rotation alone is not a pass:
the old cookie must receive a complete captured JSON 401/403 without the marker,
and the new session must still work. Old-session aliases left valid after
rotation are detected. HTML, redirects, cached/partial/redacted bodies, changed
markers, failed controls and known expiry yield no pass.

Findings contain six sanitized control/comparison exchanges, including bootstrap;
the credential-bearing login is separately recorded with its body redacted.
This profile is shared local-core functionality, not a hosted/premium feature.
