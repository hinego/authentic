package authentic

import (
	"github.com/gogf/gf/v2/net/ghttp"
	"strings"
)

func getTokenFromHeader(r *ghttp.Request, key string, HeaderName string) (string, error) {
	authHeader := r.Header.Get(key)
	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == HeaderName) {
		return "", ErrInvalidAuthHeader
	}
	return parts[1], nil
}
func getTokenFormQuery(r *ghttp.Request, key string) (string, error) {
	token := r.Get(key).String()
	if token == "" {
		return "", ErrEmptyQueryToken
	}
	return token, nil
}
func getTokenFormCookie(r *ghttp.Request, key string) (string, error) {
	cookie := r.Cookie.Get(key).String()
	if cookie == "" {
		return "", ErrEmptyCookieToken
	}
	return cookie, nil
}
