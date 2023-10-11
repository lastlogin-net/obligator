# WARNING

This is currently pre-release beta software. I don't recommend using it in
production at the moment. It has not yet undergone any sort of official
security review, and I am not a security expert. The plan is to arrange for a
security review before reaching 1.0.

That said, testing and feedback (especially with respect to security) would be
greatly appreciated.


# Introduction

obligator is a relatively simple and opinionated OpenID Connect (OIDC) Provider
(OP) server designed for selfhosters.


# Motivation

There are lots of great open source OIDC servers out there. I made obligator
because I needed a specific combination of features I didn't find in any of the
others. Primarily:

* Simple to deploy and manage. Static executable and either flat-file or sqlite
  storage
* Configurable at runtime with an API
* Passwordless email login 
* Support for [forward auth][0] 
* Support for [trusted headers][1]
* Support for upstream social login providers (GitLab, GitHub, Google, etc)


# Design

The overarching philosophy of obligator is that identities are built on email.
Email isn't perfect, but it's the globally unique federated identity we have
that works today.

Thus the purpose of obligator is to validate that a user controls an email
address as simply as possible, and communicate that to the application the
user is attempted to log in to. Validation can either be done directly
through SMTP, or delegated to upstream OIDC (and some plain OAuth2) providers.


# Running it

If you're already using docker, it's the easiest way to get started with
obligator:

```
mkdir obligator_docker

docker run --user $(id -u):$(id -g) --rm -it -v $PWD/obligator_docker:/data -v $PWD/obligator_docker:/api -p 1616:1616 anderspitman/obligator:latest -storage-dir /data -api-socket-dir /api -root-uri example.com -port 1616
```

You can also download static executables for various platforms from the
[releases][2] page.


# Using the API

Currently the API is only offered through unix sockets. This reduces the
chance that it accidentally gets exposed, which is important because
it's not authenticated in any way.

There's not any documentation, and the API is in flux, so refer to the
[source code][3] for usage.

Here's an example assuming you ran the docker command above:

```
curl --unix obligator_docker/obligator_api.sock dummy-domain/oauth2-providers
```

See [here][4] for more info on using curl over unix sockets.


# Comparison is the thief of joy

Software is rarely about right vs wrong, but rather tradeoffs. This table is
intended to help compare tradeoffs of different servers. It's also very
incomplete and probably incorrect in many cases. If you have a correction,
please submit an issue or leave a comment on the Google sheet [here][5] which
is where it's generated from.

|                          | [obligator](https://github.com/anderspitman/obligator) | [Authelia](https://www.authelia.com/) | [Authentik](https://goauthentik.io/) | [KeyCloak](https://www.keycloak.org/) | [Vouch](https://github.com/vouch/vouch-proxy) | [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) | [Dex](https://dexidp.io/) | [Ory Hydra](https://www.ory.sh/hydra/) | [Zitadel](https://zitadel.com/) | [Casdoor](https://casdoor.org/) |
| ------------------------ | ------------------------------------------------------ | ------------------------------------- | ------------------------------------ | ------------------------------------- | --------------------------------------------- | ------------------------------------------------------------ | ------------------------- | -------------------------------------- | ------------------------------- | ------------------------------- |
| Simple                   | ✅                                                      | ✅                                     | ❌                                    | ❌                                     | ❓                                             | ❓                                                            | ❓                         | ❌                                      | ❓                               | ❓                               |
| Anonymous clients        | ✅                                                      | ❌                                     | ❌                                    | ❌                                     | ❌                                             | ❌                                                            | ❌                         | ❌                                      | ❌                               | ❌                               |
| Multi-domain auth        | ✅                                                      | ❌                                     | ❌                                    | ❌                                     | ❌                                             | ❌                                                            | ❓                         | ❓                                      | ❓                               | ❓                               |
| Passwordless email login | ✅                                                      | ❌                                     | ❌                                    | ❌                                     | ❌                                             | ❌                                                            | ❌                         | ❌                                      | ❌                               | ❓                               |
| HTTP API                 | ✅                                                      | ❌                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ✅                         | ❓                                      | ❓                               | ❓                               |
| Forward auth             | ✅                                                      | ✅                                     | ✅                                    | ✅                                     | ✅                                             | ✅                                                            | ❓                         | ❌                                      | ❓                               | ❓                               |
| Trusted header auth      | ✅                                                      | ✅                                     | ❌                                    | ❌                                     | ❌                                             | ❌                                                            | ❓                         | ❓                                      | ❓                               | ❓                               |
| Upstream OIDC/OAuth2     | ✅                                                      | ❌                                     | ✅                                    | ✅                                     | ✅                                             | ✅                                                            | ✅                         | ❓                                      | ❓                               | ❓                               |
| SAML                     | ❌                                                      | ❌                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ✅                         | ❓                                      | ❓                               | ❓                               |
| LDAP                     | ❌                                                      | ✅                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ✅                         | ❓                                      | ❓                               | ❓                               |
| MFA                      | ❌                                                      | ✅                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ❓                         | ❓                                      | ❓                               | ❓                               |
| Standalone reverse proxy | ❌                                                      | ❌                                     | ✅                                    | ✅                                     | ❌                                             | ✅                                                            | ❌                         | ❓                                      | ❓                               | ❓                               |
| Admin GUI                | ❌                                                      | ✅                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ❓                         | ❓                                      | ❓                               | ❓                               |
| Language                 | Go                                                     | Go                                    | Python                               | Java                                  | Go                                            | Go                                                           | Go                        | Go                                     | Go                              | Go                              |
| Dependencies             | 1                                                      | 49                                    | 54                                   | ❓                                     | 16                                            | 36                                                           | 36                        | 58                                     | 81                              | 68                              |
| Lines of code            | ~2500                                                  | ❓                                     | ❓                                    | ❓                                     | ❓                                             | ❓                                                            | ❓                         | ❓                                      | ❓                               | ❓                               |


[0]: https://doc.traefik.io/traefik/middlewares/http/forwardauth/

[1]: https://www.authelia.com/integration/trusted-header-sso/introduction/

[2]: https://github.com/anderspitman/obligator/releases

[3]: ./api.go

[4]: https://superuser.com/q/834307

[5]: https://docs.google.com/spreadsheets/d/16Ya5KsmEpczTmoTk5J-1e2MOyuUqXIiPuj7rPfPrHAI/edit?usp=sharing
