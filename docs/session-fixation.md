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
