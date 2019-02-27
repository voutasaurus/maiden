// +heroku goVersion go1.12rc1
// +heroku install ./cmd/...

module github.com/voutasaurus/maiden

go 1.12

require (
	github.com/voutasaurus/env v0.1.0
	github.com/voutasaurus/oauth v0.0.0-20181229073404-fe85cf355555
	golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421
)
