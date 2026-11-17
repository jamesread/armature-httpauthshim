package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/jamesread/armature-httpauthshim"
	"github.com/jamesread/armature-httpauthshim/authpublic"
	"github.com/jamesread/armature-httpauthshim/providers/haslocal"
	"github.com/jamesread/armature-httpauthshim/providers/hasmtls"
	"github.com/jamesread/armature-httpauthshim/providers/hasoauth2"
	"github.com/jamesread/armature-httpauthshim/sessions"
	log "github.com/sirupsen/logrus"
)

func main() {
	cfg := exampleConfig()
	sessionStorage := sessions.NewSessionStorage(sessions.NewYAMLPersistence())

	authCtx, err := auth.NewAuthShimContext(cfg, sessionStorage)
	if err != nil {
		log.Fatalf("Failed to create auth context: %v", err)
	}

	oauth2Handler := setupProviders(cfg, authCtx)
	registerRoutes(cfg, authCtx, oauth2Handler)
	runServer(listenPort(), authCtx, oauth2Handler)
}

func exampleConfig() *authpublic.Config {
	return &authpublic.Config{
		HttpHeader: authpublic.HttpHeaderConfig{
			Enabled:      false,
			Username:     "X-Username",
			UserGroup:    "X-User-Group",
			UserGroupSep: ",",
		},
		Jwt: authpublic.JwtConfig{
			Header:         "Authorization",
			ClaimUsername:  "sub",
			ClaimUserGroup: "groups",
			CookieName:     "auth-token",
			Aud:            "httpauthshim-example",
			Issuer:         "httpauthshim-example",
		},
		LocalUsers: authpublic.LocalUsersConfig{
			Enabled: true,
			Users:   []*authpublic.LocalUser{exampleLocalUser()},
		},
		OAuth2AllowInsecureCookies: true,
		OAuth2Providers: map[string]*authpublic.OAuth2Provider{
			"github": {
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			},
		},
		OAuth2RedirectURL: "http://localhost:8080/oauth/callback",
		Mtls: authpublic.MtlsConfig{
			Enabled:              true,
			RequireClientCert:    false,
			UsernameFromCN:       true,
			UsernameFromSANEmail: false,
			GroupFromOU:          true,
			GroupFromSANDNS:      false,
		},
		AccessControlLists: []authpublic.AccessControlList{
			{
				Name:            "admin",
				MatchUsernames:  []string{"admin"},
				MatchUsergroups: []string{"admin"},
			},
		},
	}
}

func exampleLocalUser() *authpublic.LocalUser {
	// Demo-only credentials for the example; generate real hashes with haslocal.CreateHash().
	return &authpublic.LocalUser{ //nolint:gosec // G101: intentional demo credentials
		Username:  "admin",
		Usergroup: "admin",
		Password:  "$argon2id$v=19$m=65536,t=4,p=4$dGVzdHNhbHQ$testhash",
		ApiKey:    "example-api-key",
	}
}

func setupProviders(cfg *authpublic.Config, authCtx *auth.AuthShimContext) *hasoauth2.OAuth2Handler {
	if cfg.Mtls.Enabled {
		authCtx.AddProvider(hasmtls.CheckUserFromMtls)
	}
	authCtx.AddProvider(haslocal.CheckUserFromApiKey)

	if len(cfg.OAuth2Providers) == 0 {
		return nil
	}

	oauth2Handler := hasoauth2.NewOAuth2Handler(cfg, authCtx.Sessions)
	authCtx.AddProvider(oauth2Handler.CheckUserFromOAuth2Cookie)
	http.HandleFunc("/oauth/login", oauth2Handler.HandleOAuthLogin)
	http.HandleFunc("/oauth/callback", oauth2Handler.HandleOAuthCallback)
	return oauth2Handler
}

func registerRoutes(cfg *authpublic.Config, authCtx *auth.AuthShimContext, oauth2Handler *hasoauth2.OAuth2Handler) {
	http.HandleFunc("/api/protected", protectedHandler(authCtx))
	http.HandleFunc("/api/admin", adminHandler(authCtx))
	http.HandleFunc("/api/login", loginHandler(cfg, authCtx))
	http.HandleFunc("/", indexHandler(authCtx, oauth2Handler))
}

func protectedHandler(authCtx *auth.AuthShimContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := authCtx.AuthFromHttpReq(r)
		if user.IsGuest() {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, `{
			"message": "Hello, %s!",
			"username": "%s",
			"usergroup": "%s",
			"provider": "%s",
			"acls": %v
		}`, user.Username, user.Username, user.UsergroupLine, user.Provider, user.Acls)
	}
}

func adminHandler(authCtx *auth.AuthShimContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := authCtx.AuthFromHttpReq(r)
		if user.IsGuest() {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !slices.Contains(user.Acls, "admin") {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}
		writeJSON(w, `{
			"message": "Admin access granted",
			"username": "%s"
		}`, user.Username)
	}
}

func loginHandler(cfg *authpublic.Config, authCtx *auth.AuthShimContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := authenticateLocalLogin(w, r, cfg, authCtx); err != nil {
			return
		}
		writeJSON(w, `{"message": "Login successful"}`)
	}
}

func authenticateLocalLogin(w http.ResponseWriter, r *http.Request, cfg *authpublic.Config, authCtx *auth.AuthShimContext) error {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return fmt.Errorf("missing credentials")
	}
	if !haslocal.CheckUserPassword(cfg, username, password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return fmt.Errorf("invalid credentials")
	}
	sessionID, err := haslocal.NewSessionID()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	authCtx.RegisterUserSession("local", sessionID, username, "")
	haslocal.SetSessionCookie(w, r, cfg, sessionID)
	return nil
}

func indexHandler(authCtx *auth.AuthShimContext, oauth2Handler *hasoauth2.OAuth2Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := authCtx.AuthFromHttpReq(r)
		w.Header().Set("Content-Type", "text/html")
		mustFprintf(w, `<!DOCTYPE html>
<html>
<head>
	<title>HTTP Auth Shim Example</title>
</head>
<body>
	<h1>HTTP Auth Shim Example</h1>
	<p>Current user: <strong>%s</strong></p>
	<p>Provider: %s</p>
	<p>User Group: %s</p>

	<h2>Endpoints:</h2>
	<ul>
		<li><a href="/api/protected">Protected API</a> - Requires authentication</li>
		<li><a href="/api/admin">Admin API</a> - Requires admin ACL</li>
		<li><a href="/api/login">Login</a> - POST with username/password</li>
	`, user.Username, user.Provider, user.UsergroupLine)

		if oauth2Handler != nil {
			mustFprintf(w, `		<li><a href="/oauth/login?provider=github">OAuth2 Login (GitHub)</a></li>
`)
		}
		mustFprintf(w, `	</ul>
</body>
</html>`)
	}
}

func writeJSON(w http.ResponseWriter, format string, args ...any) {
	w.Header().Set("Content-Type", "application/json")
	mustFprintf(w, format, args...)
}

func mustFprintf(w http.ResponseWriter, format string, args ...any) {
	// Example responses only; production handlers should escape user-controlled content.
	if _, err := fmt.Fprintf(w, format, args...); err != nil { //nolint:gosec // G705: example HTML/JSON demo
		log.WithError(err).Warn("failed to write response")
	}
}

func listenPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		return "8080"
	}
	return port
}

func runServer(port string, authCtx *auth.AuthShimContext, oauth2Handler *hasoauth2.OAuth2Handler) {
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           nil,
		ReadHeaderTimeout: 10 * time.Second,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go serveHTTP(srv, port)
	<-sigChan
	shutdownAll(srv, authCtx, oauth2Handler)
}

func serveHTTP(srv *http.Server, port string) {
	log.Printf("Starting server on :%s", port)
	log.Printf("Visit http://localhost:%s to see the example", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func shutdownAll(srv *http.Server, authCtx *auth.AuthShimContext, oauth2Handler *hasoauth2.OAuth2Handler) {
	log.Println("Shutting down gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down server: %v", err)
	}
	if oauth2Handler != nil {
		oauth2Handler.Shutdown()
	}
	if err := authCtx.Shutdown(); err != nil {
		log.Printf("Error shutting down auth context: %v", err)
	}
	log.Println("Shutdown complete")
}
