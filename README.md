<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Rust. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Version 0.1.0. License: MIT. Crate `wsfed-caep`, edition 2021. Publishing is not set up. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

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

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

`cargo test` covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. No live iya-sts. XML signatures use exclusive canonicalization from `ua-cryptography-xml-c14n` and an RSA-SHA256 check in this crate. rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. Bearer confirmation is `urn:oasis:names:tc:SAML:2.0:cm:bearer`. This tree does not wrap another WS-Federation relying party and does not need libxml2.

## Layout

`src/` library, `wsfed-demo`, and `wsfed-caep`. `demo/` HTTP handler page and shipped `wsfed.json`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok` before the identity provider is dialed. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders and omits `signals`. Do not commit `demo/generated`. `Stop` on the poll receiver waits until the background poll loop has finished.
