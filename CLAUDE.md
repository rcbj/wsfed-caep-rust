<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Rust port of the server-side WS-Federation relying party. Crate `wsfed-caep`, edition 2021. Version 0.1.0. License MIT (`LICENSE`). Publishing is not set up. When this tree is published, `develop` and `main` are the same commit.

## Usage

`RelyingParty::from_file("wsfed.json", None)`, then `login` and `handle_reply`. JSON keys are the Node keys.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `wsfed-caep generate-keys` writes a self-signed RSA key pair. The subject key identifier is the SHA-1 of the PKCS#1 public key. Exclusive canonicalization comes from `ua-cryptography-xml-c14n`. This crate does not link libxml2 and does not wrap a WS-Federation framework.

## signals

Omitted or `true` means on. The resolved configuration leaves `signals_set` false in that case, which is the omitted key. `false` sets `signals_set` and `signals` false. It does not start the receiver and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. `stop` waits until the background poll loop has finished. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

## Tests

```sh
cargo test
```

Rust covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. No live iya-sts.

## Layout

`src/` library. `src/bin/wsfed-demo.rs` and `src/bin/wsfed-caep.rs`. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.
