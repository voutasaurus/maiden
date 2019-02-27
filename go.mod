// +heroku goVersion go1.12rc1
// +heroku install ./cmd/...

module github.com/voutasaurus/maiden

go 1.12

require (
	github.com/voutasaurus/env v0.1.0
	github.com/voutasaurus/oauth v0.0.0-20190227040719-fe28476ace2c
	golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421
)
