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

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-rust-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-rust-demo \
  wsfed-caep metadata --config demo/wsfed.json
```

The generated certificate's common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters. The subject key identifier is the SHA-1 of the PKCS#1 public key.

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
match party.decide_session(&receiver, &session_id, &login, &Access::new("read", "order", "42")) {
    Decision::Permit { obligations, .. } => { /* discharge them, then serve */ }
    Decision::Deny { .. } => { /* 403 */ }
    Decision::Unavailable { .. } => { /* 403: fail closed, never a Permit */ }
}
```

The section is off unless present, and a build without the feature refuses it. The PEP's key must be its own, and only the claims the realm's AuthZEN catalogue declares are sent. The demo protects `GET /orders/<id>` with the PEP.

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

`cargo test` covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. No live iya-sts. XML signatures use exclusive canonicalization from `ua-cryptography-xml-c14n` and an RSA-SHA256 check in this crate. rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. Bearer confirmation is `urn:oasis:names:tc:SAML:2.0:cm:bearer`. This tree does not wrap another WS-Federation relying party and does not need libxml2.

## Live sign-in

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts (main, memory mode, no persistence, no clustering) unless `IYA_STS_URL` is already set; `IYA_STS_IMAGE` starts one from an image you already have. It copies the checkout (without `demo/generated`) to a scratch build context, builds the demo image there, runs `wsfed-caep generate-keys` inside it, and registers the demo with `python3 scripts/configure_iya_sts.py`, which uses only the standard library and writes the trust chain where `idpCa` names it. It then builds the demo image again so it carries that chain, checks the image's copy matches, and runs the demo with only the key pair and the IdP metadata mounted. Cargo never runs on the host. The script signs in, emits credential-change, then session-revoked, and requires `GET /live-status` to show both. That JSON is `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It has no tokens. session-revoked leaves `signedIn` false. The last thing it prints is JSON with `"ok": true`. No script prints a password or secret, or a URL (trace lines carry fixed labels). Secrets reach `docker run` as `-e NAME`, the value in the child's environment. A generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

```sh
python3 scripts/live_iya_sts.py
IYA_STS_IMAGE=iya-sts-live:main LIVE_STS_PORT=18517 LIVE_DEMO_PORT=18617 python3 scripts/live_iya_sts.py
```

The defaults are 18517 for iya-sts and 18617 for the demo. Do not bind host ports 3000, 8081, or 18481 to 18495. The containers are `iya-sts-live-wsfed-caep-rust` and `wsfed-caep-rust-live-demo`, and the script removes both.

iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The demo ends its one session from the event handler (`App::remember` in `src/demo.rs`), as the Java demo does in `Demo.java`.

`--pep` (or `LIVE_PEP=1`) adds the embedded PEP; it needs `IYA_STS_IMAGE` built with iya-sts #2026–#2028. The install script sets the PEP up (`--pep central`), and a copy of the configuration says `local`. Central: `GET /orders/42` 200 and `POST /orders/42` 403. Local: the same, then the application's own policy is rewritten to deny read, and the GET must turn 403 by the `pep-policies-changed` event within 30 s. The install script may be run again against the same iya-sts; the live script always starts a fresh one.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then the live script at 07:06 UTC (`6 7 * * *`), and on `workflow_dispatch`. Push and pull-request CI stays in `tests.yml`.

## Demo with its embedded PEP

One command registers the demo and sets up its PEP (the demo image builds with `local`):

```sh
ADMIN_API_CLIENT_SECRET=... python3 scripts/configure_iya_sts.py --idp https://localhost:8443 --pep central
```

It needs an iya-sts with embedded-PEP support (iya-sts #2026–#2028) and the host's `openssl`. Beside the registration it creates the PEP's service account (`pep-wsfed-demo`, or `--pep-name`) in `remote-peps`, makes its P-256 key in `demo/generated/pep-key.pem` (0600, never printed, never in the image), certifies it bound to the demo's application, adds the catalogue row for `acr`, gives the application its own enforced policy (read on an order needs an `acr`; read on `attribute-protected` needs the directory attribute `attr1=abc123`; anything else is denied; the realm root is never touched), and writes the `pep` section into `demo/wsfed.json`. Mount the key into the container beside `rp.key`. Run it again with `--pep local` to switch modes: the account and key are kept, and so is the policy unless it is this script's own, which is brought up to date. Signed in, the page's **Policy enforcement** tab (`/?tab=pep`) shows the PEP's decisions, cached policy, identity and control plane in collapsible panes, refreshed every 2 s, and a **Try it** pane linking `/orders/42` and `/attribute-protected`. [docs/remote-pep.md](docs/remote-pep.md#the-demo) has the details.

**`GET /attribute-protected`** is decided on a directory attribute rather than a claim: the demo application's policy permits `read` on `attribute-protected` when the person's `attr1` is `abc123`, and the PEP asks iya-sts's PIP for it (`POST /xacml/pip`); the value is not in the assertion. The install script gives the test user `attr1=abc123`. Defining the realm's custom attribute `attr1` is a Security Administrator's act (it changes the attribute policy): it needs a token carrying `admin:security` whose subject holds `SECURITY_ADMIN`. iya-sts seeds `sts-api-client` in that role, so the script defines `attr1` itself, with an `admin:security` token minted for that one call (every other call carries `admin:read admin:write`). Where an operator has taken the client out of the role, the definition is refused; the script still tries the value (`attr1` may be defined already) and only when that fails says what to do: a Security Administrator adds it under **Directory > Policies > Attribute policy > Custom attributes** (label "Attribute 1", syntax string, one value) before the script is run again. The script rewrites the application's policy on every run while it is this script's own (PolicyId `urn:example:wsfeddemo-orders`), so a new rule reaches an existing install; a policy with another PolicyId is left as it is.

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
