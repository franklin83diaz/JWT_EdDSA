package pkg

func ParsePubPEM(s string) string {
	return `-----BEGIN PUBLIC KEY-----
` + s + `
-----END PUBLIC KEY-----`
}

func ParsePrivPEM(s string) string {
	return `-----BEGIN PRIVATE KEY-----
` + s + `
-----END PRIVATE KEY-----`
}
