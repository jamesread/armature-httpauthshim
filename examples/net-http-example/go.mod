module net-http-example

go 1.26.0

require github.com/jamesread/httpauthshim v0.2.0

require (
	github.com/alexedwards/argon2id v1.0.0 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/jamesread/golure v0.0.0-20260902093223-27b18778c9a5 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/jamesread/httpauthshim => ../..
