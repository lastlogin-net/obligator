# draft-ietf-oauth-security-topics-24

## 2.1

We are intentionally not comforming to exact `redirect_uri` matching in order
to enable anonymous clients.

We implement PKCE, nonce, and state, but we'll probably be removing state since
it's optional and redundant.

TODO: iss parameter usage??

### 2.1.1

We use PKCE for all upstream requests. Our PKCE is transaction-specific and
bound to the user agent via JWT cookies. We only support S256. We enforce
correct usage. We don't accept `code_verifier` requests if there was no
`code_challenge`.

### 2.1.2

We don't support the implicit grant

## 2.2

## 2.2.1 TODO

We don't currently implement an sender-constraining, though would certainly
like to.

## 2.2.2

We don't issue an refresh tokens

## 2.3

Our access tokens only support OIDC email via the userinfo endpoint 

## 2.4

We do not implement the password credentials grant

## 2.5 TODO

We don't currently support client authentication, but would like to

## 2.6

We implement AS metadata

TODO not sure about client manipulating `client_id`

TODO not sure about e2e TLS.

TODO do we enforce HTTPS?

We don't use postMessage

Our authorization endpoint does not use CORS
