<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Rust port of the server-side WS-Federation relying party. Crate `wsfed-caep`, edition 2021. Version 0.1.0. License MIT (`LICENSE`). A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`. When this tree is published, `develop` and `main` are the same commit.

## Usage

`RelyingParty::from_file("wsfed.json", None)`, then `login` and `handle_reply`. JSON keys are the Node keys.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `wsfed-caep generate-keys` writes a self-signed RSA key pair. The subject key identifier is the SHA-1 of the PKCS#1 public key. Exclusive canonicalization comes from `ua-cryptography-xml-c14n`. This crate does not link libxml2 and does not wrap a WS-Federation framework.

## signals

Omitted or `true` means on. The resolved configuration leaves `signals_set` false in that case, which is the omitted key. `false` sets `signals_set` and `signals` false. It does not start the receiver and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. `stop` waits until the background poll loop has finished. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

**Plain http (#12).** `httpclient::send` is the one place every fetch goes through (metadata URL, SSF configuration, JWKS, stream and poll). `refuse_plain_http_off_loopback` parses with the `url` crate ureq dials with and refuses plain `http://` to a host that is not loopback (`127.0.0.0/8`, `::1`, `localhost`) before connecting, without resolving a name, naming only the scheme and host[:port]; userinfo is never loopback, and `refuse_unsafe_characters` refuses whitespace and control characters first (the WHATWG parser would drop tabs and newlines). Redirects are not followed (`redirects(0)`), so the checked URL is the only one dialled. No opt-out. `src/test_plain_http.rs` covers it; `http://0.0.0.0:<port>` reaches a 127.0.0.1 listener on Linux, so an empty backlog proves no connection was opened.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `cargo test` in `rust:1-bookworm`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

Rust covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. No live iya-sts.

### Live sign-in and nightly

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts (main, memory mode, persistence and clustering off, no workers) unless `IYA_STS_URL` is set, or from `IYA_STS_IMAGE` when that is set. Its order is install script, then demo image build, then run: it copies the checkout (no `demo/generated`, `.git`, `target`) to a scratch context, builds the demo image there, runs `wsfed-caep generate-keys` inside it, registers the demo with `python3 scripts/configure_iya_sts.py` (standard library only, no `wsfed_caep` Python import, no Cargo; it writes the chain), builds again (only the `demo/` layer changes), checks the image's `demo/generated/idp-ca.pem` equals the saved file (`idpCaInImage` in the result), runs the demo with `rp.key`, `rp.crt` and `idp-metadata.xml` mounted file by file (never a CA, never a rewritten `idpCa`), signs in through `/authn-api`, emits credential-change and then session-revoked through `/admin-api/caep/emit`, and requires `GET /live-status` to show both, with `signedIn` false after the second. Ports default to `LIVE_STS_PORT=18517` and `LIVE_DEMO_PORT=18617`; never 3000, 8081, or 18481 to 18495. Containers: `iya-sts-live-wsfed-caep-rust`, `wsfed-caep-rust-live-demo`. A second run against an already-registered relying party needs a fresh iya-sts. No script prints a password or secret, or a URL (trace lines carry fixed labels). Secrets reach `docker run` as `-e NAME`, the value in the child's environment. A generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

`GET /live-status` is JSON: `signedIn`, `subject`, `receiver`, and `events` (`type` as the full CAEP URI, and `jti`). No tokens or assertions. iya-sts main sets the assertion SessionIndex to the assertion id, so a session-revoked event finds nobody in the index. `App::remember` in `src/demo.rs` then ends the demo's one session and untracks it. That is demo code; the library is unchanged.

`.github/workflows/nightly.yml` runs `docker build --target test .` and then `python3 scripts/live_iya_sts.py` at 07:06 UTC (`6 7 * * *`), and on `workflow_dispatch`. `tests.yml` has no schedule.

## Layout

`src/` library. `src/bin/wsfed-demo.rs` and `src/bin/wsfed-caep.rs`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`, and an explicit public URL wins over both. `scripts/trust_chain.py` saves the trust chain. `scripts/live_iya_sts.py` is the live sign-in. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. `GET /live-status` is described above. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.

## Trust chain (`idpCa`)

`idpCa` (default `file:generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`'s `save_trust_chain()` (the copy saml2-sp-rust carries; its CLI here reads `--config`/`WSFED_CONFIG` and `--idp`/`IYA_STS_URL`): the whole chain from `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), falling back to the handshake's chain, and prints the path, the anchor's subject and SHA-256. It used to keep only the root from the handshake, and only when the file was missing. `src/httpclient.rs` already adds every PEM block to the rustls root store, so the library needed no change. The demo image carries the chain from build time: `.dockerignore` is `demo/generated/*` then `!demo/generated/idp-ca.pem`, and the demo stage's `COPY demo demo` (after `cargo build`, which gets only `Cargo.*`, `src` and `demo/public` for `include_str!`, so a new chain does not rebuild the binaries) lands it at `/app/demo/generated/idp-ca.pem`. With no chain file the same COPY carries nothing from `demo/generated` and the build succeeds. Rebuild the image after re-running the install script against a different iya-sts. `src/test_trust_chain.rs` serves HTTPS from an openssl-made four-certificate chain and checks the registrar writes all four (published and handshake), that `RelyingParty` fetches metadata trusting the file, and that the leaf alone is refused.
