# LINE Login SDK for Go

[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/kkdai/line-login-sdk-go/main/LICENSE)
[![GoDoc](https://godoc.org/github.com/kkdai/line-login-sdk-go?status.svg)](https://godoc.org/github.com/kkdai/line-login-sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/kkdai/line-login-sdk-go.svg)](https://pkg.go.dev/github.com/kkdai/line-login-sdk-go)
![Go](https://github.com/kkdai/line-login-sdk-go/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/kkdai/line-login-sdk-go)](https://goreportcard.com/report/github.com/kkdai/line-login-sdk-go)

A Go SDK for [LINE Login v2.1 API](https://developers.line.biz/en/reference/line-login/) with **100% API coverage**.

> **Note:** This SDK was originally part of the Social API and has been migrated into LINE Login SDK since 2020/11/20. See [official announcement](https://developers.line.biz/en/news/2020/11/12/social-api-is-now-part-of-line-login/).

## Requirements

Go 1.23 or later.

## Installation

```bash
go get github.com/kkdai/line-login-sdk-go
```

## Supported APIs

### OAuth 2.0 / OpenID Connect

| API | Method | Description |
|-----|--------|-------------|
| [Issue access token](https://developers.line.biz/en/reference/line-login/#issue-access-token) | `GetAccessToken()` | Issues access tokens |
| [Issue access token (PKCE)](https://developers.line.biz/en/docs/line-login/integrate-pkce/) | `GetAccessTokenPKCE()` | Issues access tokens with PKCE |
| [Verify access token](https://developers.line.biz/en/reference/line-login/#verify-access-token) | `TokenVerify()` | Verifies access token validity |
| [Refresh access token](https://developers.line.biz/en/reference/line-login/#refresh-access-token) | `RefreshToken()` | Refreshes access tokens |
| [Revoke access token](https://developers.line.biz/en/reference/line-login/#revoke-access-token) | `RevokeToken()` | Revokes access tokens |
| [Verify ID token](https://developers.line.biz/en/reference/line-login/#verify-id-token) | `VerifyIDToken()` | Verifies ID token authenticity |
| [Verify ID token locally](https://developers.line.biz/en/docs/line-login/verify-id-token/) | `VerifyIDTokenLocal()` | Verifies signature (ES256 via JWKS, or HS256), `iss`, `aud`, `exp`, `nonce` without calling the verify API |

### User

| API | Method | Description |
|-----|--------|-------------|
| [Get user profile](https://developers.line.biz/en/reference/line-login/#get-user-profile) | `GetUserProfile()` | Gets user's display name, profile image, and status message |
| [Get user information](https://developers.line.biz/en/reference/line-login/#userinfo) | `GetUserInfo()` | Gets user info via OIDC userinfo endpoint |
| [Get friendship status](https://developers.line.biz/en/reference/line-login/#get-friendship-status) | `GetFriendshipStatus()` | Gets friendship status with LINE Official Account |

### App Management

| API | Method | Description |
|-----|--------|-------------|
| [Deauthorize](https://developers.line.biz/en/reference/line-login/#deauthorize) | `Deauthorize()` | Revokes user permissions (for GDPR compliance) |
| [Issue stateless channel access token](https://developers.line.biz/en/docs/basics/channel-access-token/#stateless-channel-access-tokens) | `IssueStatelessChannelAccessToken()` | Issues a 15-minute channel access token for use with `Deauthorize()` |

### Utility Functions

| Function | Description |
|----------|-------------|
| `GetWebLoginURL()` | Generates LINE Login authorization URL |
| `GetPKCEWebLoginURL()` | Generates authorization URL with PKCE |
| `PkceChallenge()` | Generates PKCE code challenge |
| `GenerateCodeVerifier()` | Generates PKCE code verifier |
| `GenerateNonce()` | Generates nonce for CSRF protection |
| `TokenResponse.DecodePayload()` | Decodes the ID token and checks `iss`/`aud`. **Does not verify the signature**; use `DecodePayloadWithOptions()` for `nonce`/`exp` checks, or `VerifyIDTokenLocal()` / `VerifyIDToken()` for full verification |
| `TokenResponse.DecodeLineProfilePlusPayload()` | Decodes ID token claims including [LINE Profile+](https://developers.line.biz/en/docs/partner-docs/line-profile-plus/) fields |

### Client Options

| Option | Description |
|--------|-------------|
| `WithHTTPClient(c *http.Client)` | Use a custom `http.Client` (timeouts, proxies, retries, etc.) |
| `WithEndpointBase(url string)` | Override the API base URL, e.g. for testing against a mock server |
| `WithAuthEndpointBase(url string)` | Override the base URL used for authorization request URLs |

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    social "github.com/kkdai/line-login-sdk-go"
)

func main() {
    // Initialize client
    client, err := social.New("YOUR_CHANNEL_ID", "YOUR_CHANNEL_SECRET")
    if err != nil {
        log.Fatal(err)
    }

    // Generate LINE Login URL
    loginURL, err := client.GetWebLoginURL(
        "https://your-callback-url.com/callback",
        "random-state",
        "profile openid email",
        social.AuthRequestOptions{},
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Login URL:", loginURL)

    // After user logs in and you receive the authorization code...
    // Exchange code for access token
    tokenResponse, err := client.GetAccessToken(
        "https://your-callback-url.com/callback",
        "AUTHORIZATION_CODE",
    ).Do()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Access Token:", tokenResponse.AccessToken)

    // Get user profile
    profile, err := client.GetUserProfile(tokenResponse.AccessToken).Do()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("User ID:", profile.UserID)
    fmt.Println("Display Name:", profile.DisplayName)

    // Get user info (OIDC)
    userInfo, err := client.GetUserInfo(tokenResponse.AccessToken).Do()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Sub:", userInfo.Sub)
}
```

## PKCE Flow Example

```go
// Generate PKCE code verifier and challenge
codeVerifier, err := social.GenerateCodeVerifier(43)
if err != nil {
    log.Fatal(err)
}
codeChallenge := social.PkceChallenge(codeVerifier)

// Generate authorization URL with PKCE
loginURL, err := client.GetPKCEWebLoginURL(
    "https://your-callback-url.com/callback",
    "random-state",
    "profile openid",
    codeChallenge,
    social.AuthRequestOptions{},
)

// Exchange code for token with PKCE
tokenResponse, err := client.GetAccessTokenPKCE(
    "https://your-callback-url.com/callback",
    "AUTHORIZATION_CODE",
    codeVerifier,
).Do()
```

## Deauthorize User (GDPR Compliance)

```go
// Deauthorize needs a channel access token, not a user access token.
// Issue a short-lived (15 min) stateless channel access token with your channel ID/secret:
tokenRes, err := client.IssueStatelessChannelAccessToken().Do()
if err != nil {
    log.Fatal(err)
}

// Revoke all user permissions
_, err = client.Deauthorize(tokenRes.AccessToken, userAccessToken).Do()
if err != nil {
    log.Fatal(err)
}
fmt.Println("User deauthorized successfully")
```

## Security Checklist

Following the [LINE Login security checklist](https://developers.line.biz/en/docs/line-login/security-checklist/):

- Use a fresh, unpredictable `state` per login (`GenerateNonce()` returns 128 random bits) and compare it with the `state` on your callback. Keep it in a server session or a same-origin cookie.
- Use an HTTPS `redirect_uri` that exactly matches the registered callback URL.
- Verify tokens on your backend. For an access token, call `TokenVerify()` and then `Validate(channelID)` on the result (checks `client_id` and `expires_in`). For an ID token, use `VerifyIDToken()` or `VerifyIDTokenLocal()` with the `nonce` you sent.
- Never expose the channel secret to clients.
- When a user unregisters from your service, call `Deauthorize()` (see above); this is required by the [development guidelines](https://developers.line.biz/en/docs/line-login/development-guidelines/).
- Keep logs for troubleshooting. `*APIError` carries the `x-line-request-id` response header in `RequestID`; log it along with the status code.

```go
res, err := client.TokenVerify(accessToken).Do()
if err == nil {
    err = res.Validate("YOUR_CHANNEL_ID")
}

if _, err := client.GetUserProfile(accessToken).Do(); err != nil {
    var apiErr *social.APIError
    if errors.As(err, &apiErr) {
        log.Printf("status=%d request_id=%s", apiErr.Code, apiErr.RequestID)
    }
}
```

## More Examples

```go
// Refresh an access token
refreshed, err := client.RefreshToken(tokenResponse.RefreshToken).Do()
if err != nil {
    log.Fatal(err)
}
fmt.Println("New Access Token:", refreshed.AccessToken)

// Verify an access token is still valid
verify, err := client.TokenVerify(tokenResponse.AccessToken).Do()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Scope:", verify.Scope, "Expires in:", verify.ExpiresIn)

// Verify an ID token and read its claims
// (calls LINE's verify API; pass the nonce you sent in the authorization request)
idTokenClaims, err := client.VerifyIDToken(tokenResponse.IDToken, social.VerifyIDTokenRequestOptions{Nonce: nonce}).Do()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Sub:", idTokenClaims.Sub)

// Or verify the ID token locally, with no extra API round trip.
// Checks the signature (ES256 via LINE's JWKS, or HS256 with your channel secret),
// iss, aud, exp and nonce. The JWKS is fetched lazily and cached for an hour.
payload, err := client.VerifyIDTokenLocal(tokenResponse.IDToken, social.VerifyIDTokenLocalOptions{Nonce: nonce}).Do()
if err != nil {
    log.Fatal(err) // errors.Is(err, social.ErrInvalidSignature) for a bad signature
}
fmt.Println("Sub:", payload.Sub, "Name:", payload.Name)

// Check friendship status with your LINE Official Account
friendship, err := client.GetFriendshipStatus(tokenResponse.AccessToken).Do()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Is friend:", friendship.FriendFlag)

// Revoke an access token (e.g. on logout)
if _, err := client.RevokeToken(tokenResponse.AccessToken).Do(); err != nil {
    log.Fatal(err)
}

// Decode and verify the ID token payload locally
payload, err := tokenResponse.DecodePayload("YOUR_CHANNEL_ID")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Name:", payload.Name)
```

## Error Handling

All API calls return an `*social.APIError` when LINE's API responds with a non-2xx status. It carries the HTTP status code and the parsed error body:

```go
profile, err := client.GetUserProfile(accessToken).Do()
if err != nil {
    var apiErr *social.APIError
    if errors.As(err, &apiErr) {
        fmt.Println("HTTP status:", apiErr.Code)
        if apiErr.Response != nil {
            fmt.Println("Message:", apiErr.Response.Message)
        }
    }
    log.Fatal(err)
}
```

## Testing

```bash
go test -v ./...
```

## Context Support

All API calls support Go context for timeout and cancellation:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

profile, err := client.GetUserProfile(accessToken).WithContext(ctx).Do()
```

## License

Licensed under the [Apache License 2.0](LICENSE)
