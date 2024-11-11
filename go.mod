module auth-proxy

go 1.23

toolchain go1.23.3

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/sessions v1.4.0
	github.com/joho/godotenv v1.5.1
	github.com/mattn/go-sqlite3 v1.14.24
	golang.org/x/oauth2 v0.24.0
)

require (
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)
