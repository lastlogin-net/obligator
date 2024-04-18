# Introduction

obligator is a relatively simple and opinionated OpenID Connect (OIDC) Provider
(OP) server designed for self-hosters.

Hacker News discussion [here][13].


# Motivation

There are lots of great open source OIDC servers out there (see
[comparison](#comparison-is-the-thief-of-joy)). I made obligator because I
needed a specific combination of features I didn't find in any of the others.
Here's a brief list. See the [feature explanation](#feature-explanation)
section for more detailed information.

* Simple to deploy and manage. Static executable and either flat-file or sqlite
  storage
* Support for anonymous OAuth2 client auth
* Authenticate to multiple domains at once
* Passwordless email login
* Configurable at runtime with an API
* Support for [forward auth][0] 
* Support for [trusted headers][1]
* Support for upstream social login providers (GitLab, GitHub, Google, etc)


# Design

The overarching philosophy of obligator is that identities are built on email.
Email isn't perfect, but it's the globally unique federated identity we have
that works today.

Thus the purpose of obligator is to validate that a user controls an email
address as simply as possible, and communicate that to the application the
user is attempting to log in to. Validation can either be done directly
through SMTP, or delegated to upstream OIDC (and some plain OAuth2) providers.


# Running it

Here's a fairly complete JSON storage file (`obligator_storage.json`). Note
that I call it "storage" and not "config" because it's not static, and more
like a simple database. obligator will update it at runtime if new values are
provided through the API.

```json
{
  "root_uri": "https://example.com",
  "login_key_name": "obligator_login_key",
  "oauth2_providers": [
    {
      "id": "google",
      "name": "Google",
      "uri": "https://accounts.google.com",
      "client_id": "<google oauth2 client_id>",
      "client_secret": "<google oauth2 client_secret>",
      "openid_connect": true
    },
    {
      "id": "lastlogin",
      "name": "LastLogin.io",
      "uri": "https://lastlogin.io",
      "client_id": "https://example.com",
      "client_secret": "",
      "openid_connect": true
    }
  ],
  "smtp": {
    "server": "smtp.fastmail.com",
    "username": "<smtp-username>",
    "password": "<smtp-password>",
    "port": 587,
    "sender": "auth@example.com",
    "sender_name": "Example"
  },
  "jwks": "<generated at first startup if empty>",
  "users": [
    {
      "email": "user1@example.com"
    },
    {
      "email": "user2@example.com"
    }
  ],
  "public": false
}
```

If you're already using docker, it's the easiest way to get started with
obligator:

```
mkdir obligator_docker/
cp obligator_storage.json obligator_docker/

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


# Support

Community support is provided on the [IndieBits forums][11].


# Feature explanation

## Anonymous OAuth2 auth

Normally in OAuth2 (and therefore OIDC), an app (client) is required to
pre-register with the provider. This can create a lot of friction, especially
if you're self-hosting an open source application. App developers are forced to
either share a single client ID for all their users (and share their
`client secret`, which essentially makes it pointless), or each user must
separately register their instance.

Instead, obligator takes essentially the approach described [here][6]. Any
OAuth2 client can anonymously authenticate with an obligator instance, with the
`client_id` equal to the domain of the client, and `client_secret` left blank.
Security is maintained through the following means:

* Only approved email addresses are permitted unless `public: true` is set in
  the config.
* The `client_id` URI must be a prefix of the `redirect_uri`, and the
  `client_id` is displayed to the user when consenting to the login. This
  guarantees that the user approves the ID token to be sent to the domain
  shown. Note that this can actually be more secure than pre-registration.
  There have been attacks in [the past][7] where users were tricked into
  authorizing apps because the pre-registered information looked convincing. By
  forcing the user to decide whether they trust the actual domain where the ID
  token will be sent, and not displaying any sort of logo which can be faked,
  security is improved.

Note that some servers implement OIDC [Dynamic Client Registration][10], which
is an official specification to accomplish some of the same goals as anonymous
auth. When an initial access token is not required (notably the case with Ory),
this can result in a very similar experience from the user perspective. The
main problem is that client apps must support dynamic client registration, and
many don't. Anonymous auth does not require any special features on the client
side.

## Multi-domain authentication

Have you ever noticed when you login to Gmail on a new computer that you're
also automatically logged in to YouTube? How does this work when Gmail is on
google.com and youtube.com doesn't have any access to the cookies or
localstorage of google.com?

The [answer][8] is that when you log in on accounts.google.com, it makes a
quick redirect to youtube.com with a URL parameter to also set up the cookies
there. I also want this functionality for all the domains protected by my OIDC
server so I'm building it into obligator.

## Passwordless email login

In line with the philosophy above, email reigns supreme in obligator. Since
passwords are relatively difficult to use securely, the way to add an email
identity is to send a confirmation code to the email address.


# Demo

There's a public instance of obligator running at https://lastlogin.io
(discovery doc at https://lastlogin.io/.well-known/openid-configuration). You
can use it with any OIDC client. Just set the `client_id` to a prefix of the
`redirect_uri` the client application uses when making the authorization
request. I like to use https://openidconnect.net/ for ad-hoc testing, like so:

1. Click on "Configuration" on the right side
2. Enter the discovery document URL, ie
   https://lastlogin.io/.well-known/openid-configuration for LastLogin
3. Click "Use Discovery Document". It should populate most of the fields
4. Set the `client_id` to https://openidconnect.net/. This is a prefix of
   the `redirect_uri` that openidconnect.net uses, which is
   https://openidconnect.net/callback
5. You can leave the `client_secret` as it is or remove it.
6. Click "Save", then "Start" to begin the flow.

The official [OpenID conformance suite][9] is also excellent for testing OIDC
servers.


# Comparison is the thief of joy

Software is rarely about right vs wrong, but rather tradeoffs. This table is
intended to help compare tradeoffs of different servers. It's also very
incomplete and probably incorrect in many cases. If you have a correction,
please submit an issue or leave a comment on the Google sheet [here][5] which
is where it's generated from.

It's generated using the excellent https://tabletomarkdown.com


|                             | [obligator](https://github.com/anderspitman/obligator) | [Portier](https://portier.github.io/) | [rauthy](https://sebadob.github.io/rauthy/) | [Authelia](https://www.authelia.com/) | [Authentik](https://goauthentik.io/) | [KeyCloak](https://www.keycloak.org/) | [Vouch](https://github.com/vouch/vouch-proxy) | [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) | [Dex](https://dexidp.io/) | [Ory Stack](https://www.ory.sh/hydra/) | [Zitadel](https://zitadel.com/) | [Casdoor](https://casdoor.org/) |
| --------------------------- | ------------------------------------------------------ | ------------------------------------- | ------------------------------------------- | ------------------------------------- | ------------------------------------ | ------------------------------------- | --------------------------------------------- | ------------------------------------------------------------ | ------------------------- | -------------------------------------- | ------------------------------- | ------------------------------- |
| Simple                      | ✅                                                      | ✅                                     | ✅                                           | ✅                                     | ❌                                    | ❌                                     | ❓                                             | ❓                                                            | ❓                         | ❌                                      | ❌                               | ❓                               |
| Anonymous auth              | ✅                                                      | ✅                                     | ✅                                           | ❌                                     | ❌                                    | ❌                                     | ❌                                             | ❌                                                            | ❌                         | ❌                                      | ❌                               | ❌                               |
| Multi-domain auth           | ✅ (planned)                                            | ❓                                     | ❓                                           | ❌                                     | ❌                                    | ❌                                     | ❌                                             | ❌                                                            | ❓                         | ❌                                      | ❓                               | ❓                               |
| Passwordless email login    | ✅                                                      | ✅                                     | ✅                                           | ❌                                     | ❌                                    | ❌                                     | ❌                                             | ❌                                                            | ❌                         | ✅                                      | ❌                               | ❓                               |
| HTTP API                    | ✅                                                      | ❓                                     | ❓                                           | ❌                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ✅                         | ✅                                      | ✅                               | ❓                               |
| Forward auth                | ✅                                                      | ❓                                     | ✅                                           | ✅                                     | ✅                                    | ✅                                     | ✅                                             | ✅                                                            | ❓                         | ✅                                      | ❓                               | ❓                               |
| Trusted header auth         | ✅ (planned)                                            | ❓                                     | ❓                                           | ✅                                     | ✅                                    | ❌                                     | ❌                                             | ❌                                                            | ❓                         | ✅                                      | ❓                               | ❓                               |
| Upstream OIDC/OAuth2        | ✅                                                      | ❌ (partial)                           | ✅                                           | ❌                                     | ✅                                    | ✅                                     | ✅                                             | ✅                                                            | ✅                         | ✅                                      | ✅                               | ❓                               |
| SAML                        | ❌                                                      | ❌                                     | ❓                                           | ❌                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ✅                         | Needs coding                           | ✅                               | ❓                               |
| LDAP                        | ❌                                                      | ❌                                     | ❓                                           | ✅                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ✅                         | Needs coding                           | ✅                               | ❓                               |
| MFA                         | ❌                                                      | ❓                                     | ✅                                           | ✅                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ❓                         | ✅                                      | ✅                               | ❓                               |
| Standalone reverse proxy    | ❌                                                      | ❌                                     | ❓                                           | ❌                                     | ✅                                    | ✅                                     | ❌                                             | ✅                                                            | ❌                         | ✅                                      | ❓                               | ❓                               |
| Admin GUI                   | ❌                                                      | ❌                                     | ✅                                           | ✅                                     | ✅                                    | ✅                                     | ❌                                             | ❌                                                            | ❓                         | ✅                                      | ✅                               | ❓                               |
| Dyanmic client registration | ✅                                                      | ❌                                     | ✅                                           | ❌                                     | ❌                                    | ❓                                     | ❌                                             | ❌                                                            | ❌                         | ✅                                      | ❌                               | ❓                               |
| Passkey support             | ❌                                                      | ❓                                     | ✅                                           | ❓                                     | ❓                                    | ❓                                     | ❓                                             | ❓                                                            | ❓                         | ❓                                      | ❓                               | ❓                               |
| Language                    | Go                                                     | Rust                                  | Rust                                        | Go                                    | Python                               | Java                                  | Go                                            | Go                                                           | Go                        | Go                                     | Go                              | Go                              |
| Dependencies                | 5                                                      | 21                                    | 73                                          | 49                                    | 54                                   | ❓                                     | 16                                            | 36                                                           | 36                        | 58                                     | 81                              | 68                              |
| Lines of code               | ~5000                                                  | ~10,000                               | ~51,000                                     | ~124,000                              | ~144,000                             | ~1,145,000                            | ~6500                                         | ~42,000                                                      | ~76,000                   | ~282,000                               | ~452,000                        | ~77,000                         |



Lines of code were generated using a similar command to this:

```bash
find . -type f -name "*.go*" -o -name "*.ts*" -o -name "*.tsx" -o -name "*.html" -o -name "*.js" -o -name "*.scss" -o -name "*.py" -o -name "*.java" -o -name "*.xml" -o -name "*.rs" | xargs cat | wc
```

Ory is calculated using Hydra + Oathkeeper + Kratos, per [this][12]

[0]: https://doc.traefik.io/traefik/middlewares/http/forwardauth/

[1]: https://www.authelia.com/integration/trusted-header-sso/introduction/

[2]: https://github.com/anderspitman/obligator/releases

[3]: ./api.go

[4]: https://superuser.com/q/834307

[5]: https://docs.google.com/spreadsheets/d/16Ya5KsmEpczTmoTk5J-1e2MOyuUqXIiPuj7rPfPrHAI/edit?usp=sharing

[6]: https://aaronparecki.com/2018/07/07/7/oauth-for-the-open-web

[7]: https://duo.com/blog/gmail-oauth-phishing-goes-viral

[8]: https://stackoverflow.com/a/19929304/943814

[9]: https://www.certification.openid.net/login.html

[10]: https://openid.net/specs/openid-connect-registration-1_0.html

[11]: https://forum.indiebits.io/c/obligator/11

[12]: https://github.com/lastlogin-io/obligator/pull/2

[13]: https://news.ycombinator.com/item?id=37848793
