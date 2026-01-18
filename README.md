# LINE Login SDK for Go

[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/kkdai/line-login-sdk-go/master/LICENSE)
[![GoDoc](https://godoc.org/github.com/kkdai/line-login-sdk-go?status.svg)](https://godoc.org/github.com/kkdai/line-login-sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/kkdai/line-login-sdk-go.svg)](https://pkg.go.dev/github.com/kkdai/line-login-sdk-go)
![Go](https://github.com/kkdai/line-login-sdk-go/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/kkdai/line-login-sdk-go)](https://goreportcard.com/report/github.com/kkdai/line-login-sdk-go)

A Go SDK for [LINE Login v2.1 API](https://developers.line.biz/en/reference/line-login/) with **100% API coverage**.

> **Note:** This SDK was originally part of the Social API and has been migrated into LINE Login SDK since 2020/11/20. See [official announcement](https://developers.line.biz/en/news/2020/11/12/social-api-is-now-part-of-line-login/).

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

### Utility Functions

| Function | Description |
|----------|-------------|
| `GetWebLoinURL()` | Generates LINE Login authorization URL |
| `GetPKCEWebLoinURL()` | Generates authorization URL with PKCE |
| `PkceChallenge()` | Generates PKCE code challenge |
| `GenerateCodeVerifier()` | Generates PKCE code verifier |
| `GenerateNonce()` | Generates nonce for CSRF protection |
| `DecodePayload()` | Decodes ID token payload |
| `DecodeLineProfilePlusPayload()` | Decodes LINE Profile+ payload |

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
    loginURL, err := client.GetWebLoinURL(
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
loginURL, err := client.GetPKCEWebLoinURL(
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
// Revoke all user permissions
// Requires channel access token, not user access token
_, err := client.Deauthorize(channelAccessToken, userAccessToken).Do()
if err != nil {
    log.Fatal(err)
}
fmt.Println("User deauthorized successfully")
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
