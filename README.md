<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Rust. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

License: MIT. Crate `wsfed-caep`, edition 2021. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

## Usage

```rust
let party = wsfed_caep::RelyingParty::from_file("wsfed.json", None)?;
let request = party.login(&wsfed_caep::LoginOptions { relay_state: Some("/".into()), ..Default::default() })?;
let who = party.handle_reply(wsfed_caep::ReplyRequest {
    method: "POST".into(),
    url: "/wsfed".into(),
    body: wsfed_caep::ReplyBody::Text(form),
}, &[request.id])?;
```

JSON keys match the Node configuration: `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, `ssf`. `file:` and `env:` prefixes are accepted. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`.

`signals` omitted or `true` is on. The resolved configuration omits the key in that case (`signals_set` stays false). `false` is kept, does not start a receiver, and does not require transmitter metadata. Sign-in is unchanged either way: WS-Federation does not send OAuth scopes. Any other value raises a config error whose message is `signals must be true or false`.

**Subjects (SSF 1.0 §8.1.3.2–8.1.3.3).** A subscribing application should receive CAEP and RISC events only about people signed in to it (iya-sts#2234 makes that iya-sts's default: an application's stream carries events only about subjects with an active session there, and Add Subject for anyone else is refused 403). The receiver says which people it cares about, so it is also right against a transmitter whose `default_subjects` is `NONE`. `SignalsReceiver::track` (a new local session) calls the transmitter's `add_subject_endpoint` with `{stream_id, subject, verified: true}`. `verified` is true because the person comes from a token this library verified. `untrack`, and a session ended by a received event, call `remove_subject_endpoint` with `{stream_id, subject}`, but only when no other local session for that person remains. The subject is the one the receiver matches events by: `iss_sub` (the transmitter's issuer and the subject attribute) when the person is known, else `email`. Each call is made once, inline on the sign-in or sign-out thread and bounded by the HTTP client's timeout. It uses the stream calls' TLS client authentication. A refusal or failure is logged through `ReceiverOptions::log` (a 403 at `warn`, since it is expected in a race; anything else at `error`) and counted in `SignalsReceiver::subjects_health()` (`added`, `removed`, `refused`, `failed`, `last_error`). It is never retried and never fails the sign-in. A 200 or 204 does not promise events (§9.1). The calls are skipped when the transmitter publishes no such endpoint, when the receiver is not running (with `signals: false` there is none), or when `ReceiverOptions::add_subjects` is false (default true; the demo reads `ssf.addSubjects`, and anything but a boolean leaves its receiver off). A session that only expires in the index is not removed at the transmitter. iya-sts narrows a stream that names subjects to those subjects, and `pep-policies-changed` is about the application. So a receiver given an embedded PEP that wants events (`ReceiverOptions::pep`) also adds the application, `{format: opaque, id: <application>}`, when it starts; without that, the first sign-in would cut the PEP off from its policy events. This was found live against iya-sts feature/2028.

**The receiver's TLS client identity (`ssf.clientCertificate`, `ssf.clientKey`).** The receiver authenticates its stream calls to the transmitter by mutual TLS. The identity it presents is its own when the `ssf` block names one: `"clientCertificate": "file:generated/ssf-client.crt"` (the leaf first, then its chain) and `"clientKey": "file:generated/ssf-client.key"` (PKCS#8, PKCS#1 or SEC1 PEM; RSA or EC). As elsewhere in the file, each may be `file:`, `env:` or an inline PEM, and a relative path is taken from the configuration's directory. Give both or neither; a pair the TLS client cannot use is refused at configuration. Without them the receiver presents the relying party's own `certificate` and `privateKey`, as before (`Resolved::ssf_tls_client()`). iya-sts's install script has the realm issue the application that certificate, which keeps the Shared Signals identity separate from the WS-Federation key pair in the RP metadata (see *Demo with its embedded PEP*).

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" -e PORT \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-rust-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-rust-demo \
  wsfed-caep metadata --config demo/wsfed.json
```

The generated certificate's subject is `CN=wsfed-caep-rust demo RP, OU=<realm>` (`--cn` names it otherwise; each part is cut at 64 characters), and its subjectAltName is the realm as a URI. The realm is the one the demo serves. That is `--realm`, which the install script passes, or else the configuration's realm moved the way the demo moves it: `--public-url` or `PUBLIC_URL` replaces the origin, otherwise `PORT` replaces a loopback port. Hence `-e PORT` above. The subject key identifier is the SHA-1 of the PKCS#1 public key.

**Plain http.** Federation metadata from a URL and every Shared Signals transmitter call (configuration, JWKS, stream, poll) use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys and Shared Signals carry SETs and the bearer token. Redirects are not followed. A URL with userinfo is never loopback, and a URL holding whitespace or a control character is refused. The `WsFedError` keeps the fetch's code (`metadata`, `ssf`) and its message names the scheme and host only. There is no opt-out. The relying party's own realm and reply URL may stay http: they are never fetched.

## Embedded PEP (features `pep` and `local`)

Ask iya-sts's authorization policy whether a signed-in person may act on a resource, through the embedded Remote PEP (the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)). **[docs/remote-pep.md](docs/remote-pep.md) is the full guide**: setting up iya-sts, choosing `central` or `local`, every configuration member, obligations, policy-change events, operating it and troubleshooting.

```toml
wsfed-caep = { version = "…", features = ["pep"] }    # central: AuthZEN at iya-sts
wsfed-caep = { version = "…", features = ["local"] }  # local too: decided in process
```

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "pep-key.pem" }
```

```rust
let decision = party.decide_session(&receiver, &session_id, &login, &Access::new("read", "order", "42"));
let status = decision.http_status(); // 200 for a Permit, 403 for anything else
match decision {
    Decision::Permit { obligations, .. } => { /* discharge them, then serve */ }
    Decision::Deny { .. } => { /* 403 */ }
    Decision::Unavailable { .. } => { /* 403: fail closed, never a Permit */ }
}
```

The section is off unless present, and a build without the feature refuses it; a section without `mode` is `local`, so a `pep`-only build must say `"mode": "central"`. The PEP's key must be its own, and only the claims the realm's AuthZEN catalogue declares are sent. Every PEP failure (no policy yet, iya-sts unreachable, an engine fault, a panic while deciding) is `Unavailable`, which `http_status()` answers 403 like a Deny; in `central` mode a failed evaluation or heartbeat also empties the Permit cache. A `SignalsReceiver` given the PEP (`ReceiverOptions::pep`) asks its stream for `pep-policies-changed` and tells the PEP whether the stream is up (`requested`/`excluded`) or `down`, so a `local` PEP polls while it cannot hear the event. The demo protects `GET /orders/<id>` and `GET /attribute-protected` with the PEP.

## Tests

```bash
docker build --target test .
```

The suite runs in a container: `cargo test --all-features`, then the default build's refusal of a `pep` section.

**AuthZEN table.** `src/test_authzen.json` is this library's own set of AuthZEN cases for the embedded PEP: catalogue rows (typed values, bags, dotted paths, short names), policies in ALFA, and sign-ins (`Login`) with an `Access` and the answer the host must see. `cargo test` runs every case in `local` mode against a stub PDP. The live half proves `central` and `local` always answer alike, against a fresh iya-sts with embedded-PEP support:

```sh
IYA_STS_IMAGE=<an iya-sts image with #2026-#2028> python3 scripts/live_authzen.py
python3 scripts/live_authzen.py --compile   # after changing the table's ALFA
```

It provisions the application, two PEPs (`central` and `local`), the catalogue and the policies, runs every case through both (`authzen_live`, in Docker), and fails when they differ or either differs from the table. Its last output is JSON with the cases run, how many were equal and as expected, and each mismatch. Against iya-sts feature/2028 with the reference fix (`iya-sts:live-2028-fga`) and iya-pep c0d61ca: 52 cases, 52 equal, 52 as expected. Ports as below (18517; never 3000, 8081, 18481 to 18495).

`cargo test` covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior and its attr1 and policy half, the embedded PEP against a stub PDP, and the demo handler (its tabs, menu and PEP pages, through a real sign-in). No live iya-sts.

**The demo's protected pages with real decisions.** `src/test_demo_decisions.rs` signs people in through the demo's own routes with a `local` PEP that holds the demo application's own policy, as iya-sts compiles the install script's ALFA (`src/test_demo_policy.json`, rewritten by `python3 scripts/live_authzen.py --compile`; a test fails when it no longer matches `orders_policy()`), against a stub PDP whose PIP answers `attr1` per person. A person with `attr1=abc123` gets 200 on `GET /attribute-protected` and `GET /orders/42`; `attr1=not-abc123`, or none, gets 403 on `/attribute-protected` (and still reads the order); `POST /orders/42` is 403; a sign-in without an `acr` gets 403 on the order; signed out is 401 with no decision asked. Every status is also checked against `Decision::http_status()` for the same session. XML signatures use exclusive canonicalization from `ua-cryptography-xml-c14n` and an RSA-SHA256 check in this crate. rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. Bearer confirmation is `urn:oasis:names:tc:SAML:2.0:cm:bearer`. This tree does not wrap another WS-Federation relying party and does not need libxml2.

## Live sign-in

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts (main, memory mode, no persistence, no clustering) unless `IYA_STS_URL` is already set; `IYA_STS_IMAGE` starts one from an image you already have. It copies the checkout (without `demo/generated`) to a scratch build context, builds the demo image there, runs `wsfed-caep generate-keys` inside it, and registers the demo with `python3 scripts/configure_iya_sts.py`, which uses only the standard library and writes the trust chain where `idpCa` names it. It then builds the demo image again so it carries that chain, checks the image's copy matches, and runs the demo with only the key pair and the IdP metadata mounted. Cargo never runs on the host. The script signs in, emits credential-change, then session-revoked, and requires `GET /live-status` to show both. That JSON is `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It has no tokens. session-revoked leaves `signedIn` false. The last thing it prints is JSON with `"ok": true`. No script prints a password or secret, or a URL (trace lines carry fixed labels). Secrets reach `docker run` as `-e NAME`, the value in the child's environment. A generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

```sh
python3 scripts/live_iya_sts.py
IYA_STS_IMAGE=iya-sts-live:main LIVE_STS_PORT=18517 LIVE_DEMO_PORT=18617 python3 scripts/live_iya_sts.py
```

The defaults are 18517 for iya-sts and 18617 for the demo. Do not bind host ports 3000, 8081, or 18481 to 18495. The containers are `iya-sts-live-wsfed-caep-rust` and `wsfed-caep-rust-live-demo`, and the script removes both.

iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The demo ends its one session from the event handler (`App::remember` in `src/demo.rs`), as the Java demo does in `Demo.java`.

`--pep` (or `LIVE_PEP=1`) adds the embedded PEP; it needs `IYA_STS_IMAGE` built with iya-sts #2026–#2028. The install script sets the PEP up (`--pep central`), and a copy of the configuration says `local`. After the install script, a second test user, `wsfed-demo-user-denied`, is created with `attr1=not-abc123`. Central: `GET /orders/42` 200, `POST /orders/42` 403, `GET /attribute-protected` 200 for the test user and 403 for the denied user (who still gets 200 on the order). Local: the same, then the application's own policy is rewritten to deny read, and the GET must turn 403 by the `pep-policies-changed` event within 30 s. The result JSON has each under `pep.central` and `pep.local` (`attributeProtectedIs200`, `denied`).

**UI test.** A real headless browser through the demo's real pages:

```bash
IYA_STS_IMAGE=<an iya-sts image with #2026-#2028> python3 scripts/live_ui.py
```

`scripts/live_ui.py` (also `live_iya_sts.py --ui` or `LIVE_UI=1`) provisions as the live run does (a fresh iya-sts on the same ports, the install script with `--pep local`, both test users, the demo image built and run; containers `iya-sts-live-wsfed-caep-rust-ui` and `wsfed-caep-rust-live-ui-demo`), then runs `scripts/live_ui_browser.py` in Playwright's image (`mcr.microsoft.com/playwright/python:v1.49.0-noble`, `--network host`; the image has the browsers, and the container installs the `playwright` package in its own `/tmp`, nothing on the host). Chromium opens the demo, clicks Sign in, completes iya-sts's sign-in page, lands back through the wresult form post, and checks the page response's HTTP status and heading: `/attribute-protected` and `/orders/42` 200 for the test user, by address and by the top bar's links; then Sign out from the user menu, the denied user (through Sign in with another account if a session lingers): `/attribute-protected` 403, `GET /orders/42` 200, and `POST /orders/42` 403 through `page.request` with the browser's cookies. Screenshots go to `LIVE_UI_OUT` or a new temporary directory (never the checkout). It prints JSON last and exits 1 on any mismatch. The browser accepts iya-sts's own-CA certificate with `ignore_https_errors`. The install script may be run again against the same iya-sts; the live script always starts a fresh one.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then the live script at 07:06 UTC (`6 7 * * *`), and on `workflow_dispatch`. Push and pull-request CI stays in `tests.yml`.

## Demo with its embedded PEP

**Shared Signals identity.** With an `ssf` block, the install script lets the application manage its own stream (`oauthAllowedScope` `ssf.manage`, a member of `SSF_MANAGE`). It then has the realm issue the application a TLS client certificate (`POST /admin-api/applications/issue-tls-client-certificate`, `keyAlg` `ec-p256`, from the realm's tls-client Issuing CA, subjectAltName `urn:sts:application:<realm>`). The key goes to `demo/generated/ssf-client.key`: mode 0600, decrypted with the host's `openssl` from the one-time encrypted PEM, never printed. The leaf and chain go to `demo/generated/ssf-client.crt`, and the script names both in `ssf.clientKey` and `ssf.clientCertificate`. iya-sts's `/ssf/*` takes that certificate as the application itself while the application's record lists it, with the scopes a token for it would get. A re-run keeps a certificate the application still holds (its serial is on `page.mtls.certificates`); a revoked one, or one from another iya-sts, is replaced. Earlier versions pinned the RP's self-signed certificate instead, in iya-sts's process-wide client-certificate truststore (`tls/trust/add`) and on the application's entry (`add-certificate`). Once the new certificate is in place, the script removes both by that certificate's SHA-256 (`tls/trust/remove`, `applications/remove-certificate`). Neither being there is no error. Compose mounts `demo/generated` read-only, so the demo finds the files; `.dockerignore` keeps them out of the image.

One command registers the demo and sets up its PEP (the demo image builds with `local`):

```sh
ADMIN_API_CLIENT_SECRET=... python3 scripts/configure_iya_sts.py --idp https://localhost:8443 --pep central
```

A bare `--pep` is `local`. It needs an iya-sts with embedded-PEP support (iya-sts #2026–#2028) and the host's `openssl`. Beside the registration it creates the PEP's service account (`pep-wsfed-demo`, or `--pep-name`) in `remote-peps`, makes its P-256 key in `demo/generated/pep-key.pem` (0600, never printed, never in the image), certifies it bound to the demo's application, adds the catalogue row for `acr`, gives the application its own enforced policy (read on an order needs an `acr`; read on `attribute-protected` needs the directory attribute `attr1=abc123`; anything else is denied; the realm root is never touched), and writes the `pep` section into `demo/wsfed.json`. Compose mounts `demo/generated`, key included, into the container read-only. Run it again with `--pep local` to switch modes: the account and key are kept, and so is the policy unless it is this script's own, which is brought up to date. Signed in, the page's **Policy enforcement** tab (`/?tab=pep`) shows the PEP's decisions, cached policy, identity and control plane in collapsible panes, refreshed every 2 s, and a **Try it** pane linking `/orders/42` and `/attribute-protected`. [docs/remote-pep.md](docs/remote-pep.md#the-demo) has the details.

**`GET /attribute-protected`** is decided on a directory attribute rather than a claim: the demo application's policy permits `read` on `attribute-protected` when the person's `attr1` is `abc123`, and the PEP asks iya-sts's PIP for it (`POST /xacml/pip`); the value is not in the assertion. The install script gives the test user `attr1=abc123`. Defining the realm's custom attribute `attr1` is a Security Administrator's act (it changes the attribute policy): it needs a token carrying `admin:security` whose subject holds `SECURITY_ADMIN`. iya-sts seeds `sts-api-client` in that role, so the script defines `attr1` itself, with an `admin:security` token minted for that one call (every other call carries `admin:read admin:write`). Where an operator has taken the client out of the role, the definition is refused; the script still tries the value (`attr1` may be defined already) and only when that fails says what to do: a Security Administrator adds it under **Directory > Policies > Attribute policy > Custom attributes** (label "Attribute 1", syntax string, one value) before the script is run again. The script rewrites the application's policy on every run while it is this script's own (PolicyId `urn:example:wsfeddemo-orders`), so a new rule reaches an existing install; a policy with another PolicyId is left as it is.

## Credentials

Every credential the library, the demo and its scripts use: what it is, where it lives, and how it is replaced. Paths are relative to `demo/`. No script prints a key, a password or a secret: only paths.

### The application's own credentials

These are the relying party's own credentials, for its WS-Federation registration and sign-in and for its Shared Signals stream.

| Credential | What it is | Made or issued by | Where it lives | Used for | How iya-sts learns of it | Rotation |
|---|---|---|---|---|---|---|
| WS-Federation key pair | An RSA key (3072 bits by default; `--bits` 2048, 3072 or 4096) and a self-signed certificate valid for 1095 days (`--days`). The subject is `CN=wsfed-caep-rust demo RP, OU=<realm>` with a subjectAltName URI of the realm. | `wsfed-caep generate-keys`, run inside the demo image. The install script runs it when neither file exists and `wsfed-caep` is on its PATH, which is the case only inside the image. | `privateKey` → `generated/rp.key` (0600, PKCS#8) and `certificate` → `generated/rp.crt` (0644). | Decrypting encrypted assertions (`wantAssertionsEncrypted` needs it); its certificate is the encryption key (`KeyDescriptor use="encryption"`) in the relying party's metadata. WS-Federation signs nothing here, and the metadata is not signed. It is also the receiver's TLS client identity when the configuration names no `ssf.clientCertificate`. | It doesn't need to. The registration is the realm and the reply URL. The install script writes `generated/rp-metadata.xml` but doesn't upload it, and iya-sts's passive WS-Federation profile doesn't encrypt tokens. Earlier versions of the install script pinned this certificate for Shared Signals; the current one removes that (see below). | `generate-keys --force` (with `-e PORT`, or `--realm`), then run the install script again to rewrite `rp-metadata.xml`, then restart the demo. Nothing at iya-sts breaks. An identity provider that encrypts to the old certificate needs the new metadata first. |
| Shared Signals client certificate | An EC P-256 key and a TLS client certificate (`clientAuth`, subjectAltName `urn:sts:application:<realm>`), with its chain. | iya-sts's realm tls-client Issuing CA, through `POST /admin-api/applications/issue-tls-client-certificate` (`keyAlg` `ec-p256`), called by the install script. The one-time encrypted key is decrypted with the host's `openssl`. | `ssf.clientKey` → `generated/ssf-client.key` (0600, PKCS#8) and `ssf.clientCertificate` → `generated/ssf-client.crt` (leaf, then chain). Both are named in `wsfed.json` by the install script. `.dockerignore` keeps them out of the image, and compose mounts `generated/` read-only. | Mutual TLS on every call the receiver makes to `/ssf/*`: stream discovery and creation, polls, verification, Add and Remove Subject. iya-sts takes it as the application itself, with the scopes a token for the application would get (`oauthAllowedScope` `ssf.manage` and the `SSF_MANAGE` role). | iya-sts issued it, and the application's record lists it (by serial). It stops working at the next call once the record no longer lists it or it is revoked. | Revoke it on the application's page (its TLS client certificates), or delete the two files, then run the install script again (it issues a new one) and restart the demo. A re-run keeps a certificate the application still holds. Revoked or not listed, `/ssf/*` answers 401 and the receiver stops. |
| Fallback: the WS-Federation key pair at `/ssf/*` | The row above's key pair, presented when `ssf.clientCertificate` and `ssf.clientKey` are absent (`Resolved::ssf_tls_client()`). | (as above) | (as above) | Mutual TLS at `/ssf/*`. | Only if an administrator trusts that self-signed certificate (a client-certificate trust anchor and the same certificate stored on the application); the install script no longer sets this up. | (as above) |
| Test user's password | The password of `wsfed-demo-user` (`--test-user`). | `WSFED_DEMO_USER_PASSWORD` when set; otherwise iya-sts generates one when the install script creates the user. | `generated/wsfed-demo-user.password` (0600), written only when iya-sts generated it. Only the path is printed. | Signing in at iya-sts's sign-in page. | It is iya-sts's directory entry. | Set `WSFED_DEMO_USER_PASSWORD` and run the install script again (it sets the password on an existing user), or change it on the console. Without the variable, an existing user's password is left as it is. |
| Session cookie key | 32 random bytes per demo process, used for HMAC. | `App::new`. | Memory only. | Signing the `sid` and `wsfed_pending` cookies. | It doesn't. | Every restart; everyone signed in to the demo is signed out. |

The live and UI scripts make their own users and passwords for each run and keep them in memory. They reach containers as `-e NAME`, with the value in the child's environment.

### The embedded PEP's credentials

The PEP is a separate client of iya-sts with an identity of its own; [docs/remote-pep.md](docs/remote-pep.md#credentials) has the details.

| Credential | What it is | Made or issued by | Where it lives | Used for | Rotation |
|---|---|---|---|---|---|
| The PEP's service account | `pep-wsfed-demo` (`--pep-name`): a service account with no password (`credential: none`), owned by `admin-write`, and a member of `remote-peps`. | The install script (`--pep`), only when `GET /users?user=` says it doesn't exist. | iya-sts's directory; the `pep` section's `name`. | Being the PEP: the bound application, registration and audit name it. | Kept on every run. |
| The PEP's key | An EC P-256 key. | Made on the host with `openssl genpkey`. Only its certificate request (`CN=<name>`) is sent, to `POST /admin-api/xacml/issue-pep-credential` with `application` = the realm, which certifies the key and binds the PEP to the application. | `pep.assertionKey` → `generated/pep-key.pem` (0600). It is never printed and never in the image. | Signing the PEP's RFC 7523 assertion for a DPoP-bound (RFC 9449) access token through the client `sts-remote-pep`, and every DPoP proof. | `--pep` keeps an existing key and only binds it again (`set-pep-application`). To replace it, delete the file and run `--pep <mode>` again (a new key, certified), then revoke the old one on the console. The PEP reads the file again when it changes. |

The library refuses a PEP key that is one of the application's own keys. `RelyingParty::create` refuses `pep.assertionKey` equal to `privateKey`, and `SignalsReceiver::new` refuses it equal to the receiver's TLS client key; both compare JWK thumbprints. A key shared between them would let whoever holds the application's key obtain the PEP's tokens and act as the PEP, and replacing one would replace the other.

### Install-time only

| Credential | What it is | Where it lives | Used for |
|---|---|---|---|
| The management client's secret | The secret of iya-sts's `sts-api-client`. | `ADMIN_API_CLIENT_SECRET` (or `STS_ADMIN_API_CLIENT_SECRET`) in the environment of `scripts/configure_iya_sts.py`. It is never written to a file or printed. The live scripts pass it to their iya-sts container as `-e NAME`. | A `client_credentials` token with `admin:read admin:write` for `<base>/admin-api`, used for every management call. A second token, `admin:read admin:security`, is minted only for the one call that defines the realm's custom attribute `attr1` (iya-sts seeds `sts-api-client` in `SECURITY_ADMIN`). |

Neither the demo nor the library ever sees this secret.

### Trust material

All of it is public; none of it is a secret.

| What | Where | What it verifies |
|---|---|---|
| iya-sts's listener CA chain | `idpCa` → `generated/idp-ca.pem`, written by the install script on every run through `scripts/trust_chain.py` and copied into the demo image. It is trusted on first use: compare the anchor it prints with the Root CA on iya-sts's PKI page. | iya-sts's TLS certificate, for the metadata fetch, every Shared Signals call, and the PEP's calls (`pep.tlsCa` defaults to `idpCa`). |
| The identity provider's metadata | `idpMetadata` → `generated/idp-metadata.xml`, fetched by the install script from `<base>/wsfed/metadata/<realm>`. | The XML signature on every security token, through the signing certificates it lists. |
| The transmitter's JWKS | Fetched at run time from the transmitter's `jwks_uri`, and refreshed when a SET names a key it doesn't hold. | The signature on every Security Event Token. |
| The relying party's metadata | `generated/rp-metadata.xml`, written by the install script. | Nothing here; it is for an identity provider that wants this relying party's encryption certificate. |

### Development and product iya-sts

- **Realm-issued certificates work in both modes.** A certificate iya-sts issues chains to its Service Root. The main port trusts that Root while `tls.trustIssuedClientCertificates` is on (the default), so nothing has to be pinned in its client-certificate truststore.
- **Why not pin the RP's certificate.** That truststore is process-wide: it applies to the main port, and to LDAPS on 636, for every realm. A self-signed certificate added there is trusted everywhere and ties the Shared Signals identity to the WS-Federation key pair. That is why the install script has the realm issue a certificate and removes the anchor earlier versions added. GNAP's product default (`gnap.mtlsTrust` `pki`) refuses a self-signed client certificate outright; gnap-caep-risc-rust moved to realm-issued certificates for that reason.
- **Development checks fewer passwords.** iya-sts's development sign-in page checks no password: the username is the identity. Product checks the test user's password. Development also accepts any Basic password at `/ssf/*` except a reserved one, but this receiver never uses Basic.
- **The PEP's credential is the same in both modes:** its certified key and the `remote-peps` membership.

## Layout

`src/` library, `wsfed-demo`, and `wsfed-caep`. `demo/` HTTP handler page and shipped `wsfed.json`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `scripts/trust_chain.py` saves iya-sts's listener CA trust chain. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok` before the identity provider is dialed. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders and omits `signals`.

Signed in, the page has three tabs, and every block on them is a collapsible pane (a **Collapse all** / **Expand all** button opens or closes the tab's panes):

- **Session** (`/`): the protections in effect (the signed and, when so, encrypted assertion, audience, bearer confirmation, validity and clock skew, replay, wctx, TLS, the session cookie, Shared Signals); who signed in (NameID, issuer, realm, authentication instant and context, SessionIndex, and every claim with its FriendlyName); the credential cache (kept in this process, the assertion's and the identity provider's session's validity, whether the receiver tracks it; WS-Federation has no refresh token); and the credentials: the security token's facts (WS-Trust version, TokenType, AppliesTo, Lifetime, signature or encryption methods, signing certificate) and this relying party's and the identity provider's certificates. Every value is shown by a SHA-256 fingerprint, never the token, assertion or key itself.
- **CAEP & RISC events** (`/?tab=events`): the stream's status, a button that asks the transmitter for a verification event (`SignalsReceiver::verify`), and the log of every event received, newest first, drawn live by `demo/public/app.js` from `GET /api/signals?after=<id>` (401 without a sign-in; `GET /events` answers 204, so the script polls). The tab says it shows every user's events: a real application must show a person only their own.
- **Policy enforcement** (`/?tab=pep`): the embedded PEP, above.

The top bar has the demo's links (Demo home, and with the PEP Attribute-protected and Order 42) and a user menu: the avatar and name (the username claim, else `upn`, else iya-sts's `name` claim, else `preferred_username`; the NameID only when none is there), **Sign in with another account** (`/login?prompt=login`, which sends `wfresh=0`), and **Sign out**, which is nowhere else. Each page script (`app.js`, `panes.js`, `menu.js`, `pep.js`) runs in its own function scope. Do not commit `demo/generated`. `Stop` on the poll receiver waits until the background poll loop has finished.

## iya-sts trust chain (`idpCa`)

`idpCa` names iya-sts's TLS listener CA trust chain; in `demo/wsfed.json` it is `file:generated/idp-ca.pem` (relative to `demo/`). The library adds every certificate in that file to its rustls trust store, so a whole chain works and the path ends at the Root. It reads it for the metadata fetch and the Shared Signals receiver.

`scripts/configure_iya_sts.py` writes it on every run (through `scripts/trust_chain.py`'s `save_trust_chain()`): the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that endpoint is missing. It prints the path, the trust anchor's subject, and its SHA-256; compare the anchor with the Root CA on iya-sts's Server configuration, PKI page. The fetch itself is not verified (trust on first use). `python3 scripts/trust_chain.py --config demo/wsfed.json --idp https://localhost:8081` refreshes only the chain.

The demo image build copies that file in: `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated/` (keys and metadata stay out), and `COPY demo demo`, after `cargo build`, puts it at `/app/demo/generated/idp-ca.pem`, where `idpCa` names it. A build with no chain file yet (a fresh clone, CI) still succeeds and carries none. Generate the key pair in the image, run the install script, then build the image again; after running the install script against a different iya-sts, rebuild (`docker compose up --build`). Compose also mounts `demo/generated`, which holds the same file.
