package apiservice

const (
	LINE_SOCIAL_API string = "https://access.line.me/oauth2/v2.1/"
)

func getAuthAPI() string {
	return LINE_SOCIAL_API + "authorize"
}

func getTokenAPI() string {
	return LINE_SOCIAL_API + "token"
}
