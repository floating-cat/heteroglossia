package conf

import "crypto/subtle"

type HTTPSOCKSAuthInfo struct {
	Username string
	Password string
}

func (authInfo *HTTPSOCKSAuthInfo) IsEmpty() bool {
	return authInfo == nil || (authInfo.Username == "" && authInfo.Password == "")
}

func (authInfo *HTTPSOCKSAuthInfo) NotEqual(anotherAuthInfo *HTTPSOCKSAuthInfo) bool {
	return authInfo.NotEqual2(anotherAuthInfo.Username, anotherAuthInfo.Password)
}

func (authInfo *HTTPSOCKSAuthInfo) NotEqual2(username, password string) bool {
	usernameEq := subtle.ConstantTimeCompare([]byte(authInfo.Username), []byte(username))
	passwordEq := subtle.ConstantTimeCompare([]byte(authInfo.Password), []byte(password))
	return usernameEq != 1 || passwordEq != 1
}
