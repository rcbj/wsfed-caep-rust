<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Rust. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Version 0.1.2. License: MIT. Crate `wsfed-caep`, edition 2021. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

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

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

`cargo test` covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. No live iya-sts. XML signatures use exclusive canonicalization from `ua-cryptography-xml-c14n` and an RSA-SHA256 check in this crate. rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. Bearer confirmation is `urn:oasis:names:tc:SAML:2.0:cm:bearer`. This tree does not wrap another WS-Federation relying party and does not need libxml2.

## Live sign-in

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts (main, memory mode, no persistence, no clustering) unless `IYA_STS_URL` is already set; `IYA_STS_IMAGE` starts one from an image you already have. It copies the checkout (without `demo/generated`) to a scratch build context, builds the demo image there, runs `wsfed-caep generate-keys` inside it, and registers the demo with `python3 scripts/configure_iya_sts.py`, which uses only the standard library and writes the trust chain where `idpCa` names it. It then builds the demo image again so it carries that chain, checks the image's copy matches, and runs the demo with only the key pair and the IdP metadata mounted. Cargo never runs on the host. The script signs in, emits credential-change, then session-revoked, and requires `GET /live-status` to show both. That JSON is `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It has no tokens. session-revoked leaves `signedIn` false. The last thing it prints is JSON with `"ok": true`. No script prints a password or secret, or a URL (trace lines carry fixed labels). Secrets reach `docker run` as `-e NAME`, the value in the child's environment. A generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

```sh
python3 scripts/live_iya_sts.py
IYA_STS_IMAGE=iya-sts-live:main LIVE_STS_PORT=18517 LIVE_DEMO_PORT=18617 python3 scripts/live_iya_sts.py
```

The defaults are 18517 for iya-sts and 18617 for the demo. Do not bind host ports 3000, 8081, or 18481 to 18495. The containers are `iya-sts-live-wsfed-caep-rust` and `wsfed-caep-rust-live-demo`, and the script removes both.

iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The demo ends its one session from the event handler (`App::remember` in `src/demo.rs`), as the Java demo does in `Demo.java`.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then the live script at 07:06 UTC (`6 7 * * *`), and on `workflow_dispatch`. Push and pull-request CI stays in `tests.yml`.

## Layout

`src/` library, `wsfed-demo`, and `wsfed-caep`. `demo/` HTTP handler page and shipped `wsfed.json`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `scripts/trust_chain.py` saves iya-sts's listener CA trust chain. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok` before the identity provider is dialed. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders and omits `signals`. Do not commit `demo/generated`. `Stop` on the poll receiver waits until the background poll loop has finished.

## iya-sts trust chain (`idpCa`)

`idpCa` names iya-sts's TLS listener CA trust chain; in `demo/wsfed.json` it is `file:generated/idp-ca.pem` (relative to `demo/`). The library adds every certificate in that file to its rustls trust store, so a whole chain works and the path ends at the Root. It reads it for the metadata fetch and the Shared Signals receiver.

`scripts/configure_iya_sts.py` writes it on every run (through `scripts/trust_chain.py`'s `save_trust_chain()`): the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that endpoint is missing. It prints the path, the trust anchor's subject, and its SHA-256; compare the anchor with the Root CA on iya-sts's Server configuration, PKI page. The fetch itself is not verified (trust on first use). `python3 scripts/trust_chain.py --config demo/wsfed.json --idp https://localhost:8081` refreshes only the chain.

The demo image build copies that file in: `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated/` (keys and metadata stay out), and `COPY demo demo`, after `cargo build`, puts it at `/app/demo/generated/idp-ca.pem`, where `idpCa` names it. A build with no chain file yet (a fresh clone, CI) still succeeds and carries none. Generate the key pair in the image, run the install script, then build the image again; after running the install script against a different iya-sts, rebuild (`docker compose up --build`). Compose also mounts `demo/generated`, which holds the same file.
