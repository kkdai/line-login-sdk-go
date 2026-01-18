package social

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// BasicResponse type
type BasicResponse struct {
}

type errorResponseDetail struct {
	Message  string `json:"message"`
	Property string `json:"property"`
}

// ErrorResponse type
type ErrorResponse struct {
	Message string                `json:"message"`
	Details []errorResponseDetail `json:"details"`
}

// UserProfileResponse type
type UserProfileResponse struct {
	UserID        string `json:"userId"`
	DisplayName   string `json:"displayName"`
	PictureURL    string `json:"pictureUrl"`
	StatusMessage string `json:"statusMessage"`
}

type BasicPayload struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int      `json:"exp"`
	Iat      int      `json:"iat"`
	AuthTime int      `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	Amr      []string `json:"amr"`
	Name     string   `json:"name"`
	Picture  string   `json:"picture"`
	Email    string   `json:"email"`
}

// LineProfilePlusPayload https://developers.line.biz/en/docs/partner-docs/line-profile-plus/#id-token
type LineProfilePlusPayload struct {
	BasicPayload
	GivenName               string  `json:"given_name"`
	GivenNamePronunciation  string  `json:"given_name_pronunciation"`
	MiddleName              string  `json:"middle_name"`
	FamilyName              string  `json:"family_name"`
	FamilyNamePronunciation string  `json:"family_name_pronunciation"`
	Gender                  string  `json:"gender"`
	Birthdate               string  `json:"birthdate"`
	PhoneNumber             string  `json:"phone_number"`
	Address                 Address `json:"address"`
}

// Address https://developers.line.biz/en/docs/partner-docs/line-profile-plus/#address-object
type Address struct {
	PostalCode    string `json:"postal_code"`
	Region        string `json:"region"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"street_address"`
	Country       string `json:"country"`
}

// Token verification reponse
type TokenVerifyResponse struct {
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	ExpiresIn int    `json:"expires_in"`
}

// Token refresh type
type TokenRefreshResponse struct {
	// TokenType: Bearer
	TokenType string `json:"token_type"`

	// Scope: Permissions granted by the user. For more information, see Scopes.
	//profile: Permission to get the user's profile information.
	//openid: Used to retrieve an ID token. For more information, see ID tokens.
	//email: Permission to get the user's email address. openid must be specified at the same time. For more information, see ID tokens.
	Scope string `json:"scope"`

	// AccessToken: Access token. Valid for 30 days.
	AccessToken string `json:"access_token"`

	// ExpiresIn: Amount of time in seconds until the access token expires
	ExpiresIn int `json:"expires_in"`

	// RefreshToken: Which token you want to refresh.
	//Token used to get a new access token. Valid up until 10 days after the access token expires.
	RefreshToken string `json:"refresh_token"`
}

// VerifyIDTokenResponse type
type VerifyIDTokenResponse struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int      `json:"exp"`
	Iat      int      `json:"iat"`
	AuthTime int      `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	Amr      []string `json:"amr"`
	Name     string   `json:"name"`
	Picture  string   `json:"picture"`
	Email    string   `json:"email"`
}

// GetUserProfileResponse type
type GetUserProfileResponse struct {
	// UserID: Identifier of the user
	UserID string `json:"userId"`

	// DisplayName: User's display name
	DisplayName string `json:"displayName"`

	// PictureURL: Profile image URL. "https" image URL. Not included in the response if the user doesn't have a profile image.
	PictureURL string `json:"pictureUrl"`

	//StatusMessage: User's status message. Not included in the response if the user doesn't have a status message.
	StatusMessage string `json:"statusMessage"`
}

// GetFriendshipStatusResponse type
type GetFriendshipStatusResponse struct {
	// FriendFlag: true if the user has added the bot as a friend and has not blocked the bot. Otherwise, false.
	FriendFlag bool `json:"friendFlag"`
}

// GetUserInfoResponse type
// OIDC-compliant response from /oauth2/v2.1/userinfo endpoint
// https://developers.line.biz/en/reference/line-login/#userinfo
type GetUserInfoResponse struct {
	// Sub: User ID
	Sub string `json:"sub"`

	// Name: User's display name. Only included if the profile scope was specified.
	Name string `json:"name,omitempty"`

	// Picture: User's profile image URL. Only included if the profile scope was specified.
	Picture string `json:"picture,omitempty"`
}

// TokenResponse type
type TokenResponse struct {
	// AccessToken: Access token. Valid for 30 days.
	AccessToken string `json:"access_token"`

	// ExpiresIn: Amount of time in seconds until the access token expires
	ExpiresIn int `json:"expires_in"`

	// IDToken: JSON Web Token (JWT) that includes information about the user.
	//This field is returned only if openid is specified in the scope. For more information, see ID tokens.
	IDToken string `json:"id_token"`

	// RefreshToken: Which token you want to refresh.
	//Token used to get a new access token. Valid up until 10 days after the access token expires.
	RefreshToken string `json:"refresh_token"`

	// Scope: Permissions granted by the user. For more information, see Scopes.
	//profile: Permission to get the user's profile information.
	//openid: Used to retrieve an ID token. For more information, see ID tokens.
	//email: Permission to get the user's email address. openid must be specified at the same time. For more information, see ID tokens.
	Scope string `json:"scope"`

	// TokenType: Bearer
	TokenType string `json:"token_type"`
}

// DecodePayload : decode payload result.
func (t TokenResponse) DecodePayload(channelID string) (*BasicPayload, error) {
	splitToken := strings.Split(t.IDToken, ".")
	if len(splitToken) != 3 {
		return nil, fmt.Errorf("idToken size is wrong")
	}

	payloadSegment := splitToken[1]
	decodedPayload, err := b64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return nil, fmt.Errorf("base64url decode error: %w", err)
	}

	retPayload := &BasicPayload{}
	if err := json.Unmarshal(decodedPayload, retPayload); err != nil {
		return nil, fmt.Errorf("json unmarshal error: %v", err)
	}

	// payload verification
	if retPayload.Iss != "https://access.line.me" {
		return nil, fmt.Errorf("payload verification failed: wrong issuer")
	}

	if retPayload.Aud != channelID {
		return nil, fmt.Errorf("payload verification failed: wrong audience")
	}

	return retPayload, nil
}

// DecodeLineProfilePlusPayload : decode line profile+ payload result.
// https://developers.line.biz/en/docs/partner-docs/line-profile-plus/#id-token
func (t TokenResponse) DecodeLineProfilePlusPayload(channelID string) (*LineProfilePlusPayload, error) {
	splitToken := strings.Split(t.IDToken, ".")
	if len(splitToken) < 3 {
		return nil, fmt.Errorf("idToken size is wrong")
	}

	payloadSegment := splitToken[1]
	decodedPayload, err := b64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return nil, fmt.Errorf("base64url decode error: %w", err)
	}

	retPayload := &LineProfilePlusPayload{}
	if err := json.Unmarshal(decodedPayload, retPayload); err != nil {
		return nil, fmt.Errorf("json unmarshal error: %w", err)
	}

	if retPayload.Iss != "https://access.line.me" {
		return nil, fmt.Errorf("payload verification failed: wrong issuer")
	}

	if retPayload.Aud != channelID {
		return nil, fmt.Errorf("payload verification failed: wrong audience")
	}

	return retPayload, nil
}

func checkResponse(res *http.Response) error {
	if res.StatusCode != http.StatusOK {
		decoder := json.NewDecoder(res.Body)
		result := ErrorResponse{}
		if err := decoder.Decode(&result); err != nil {
			return &APIError{
				Code: res.StatusCode,
			}
		}
		return &APIError{
			Code:     res.StatusCode,
			Response: &result,
		}
	}
	return nil
}

func decodeToBasicResponse(res *http.Response) (*BasicResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := BasicResponse{}
	if err := decoder.Decode(&result); err != nil {
		if err == io.EOF {
			return &result, nil
		}
		return nil, err
	}
	return &result, nil
}

func decodeToTokenResponse(res *http.Response) (*TokenResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := TokenResponse{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeToTokenVerifyResponse(res *http.Response) (*TokenVerifyResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := TokenVerifyResponse{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeToTokenRefreshResponse(res *http.Response) (*TokenRefreshResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := TokenRefreshResponse{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeToVerifyIDTokenResponse(res *http.Response) (*VerifyIDTokenResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := VerifyIDTokenResponse{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeToGetUserProfileResponse(res *http.Response) (*GetUserProfileResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := GetUserProfileResponse{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeToGetFriendshipStatusResponse(res *http.Response) (*GetFriendshipStatusResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := GetFriendshipStatusResponse{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func decodeToGetUserInfoResponse(res *http.Response) (*GetUserInfoResponse, error) {
	if err := checkResponse(res); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(res.Body)
	result := GetUserInfoResponse{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
