package main

import (
	"log"
	"net/http"
	"os"

	"github.com/voutasaurus/env"
	"github.com/voutasaurus/oauth"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	logger := log.New(os.Stderr, "oauthtest: ", log.Llongfile|log.LstdFlags|log.LUTC)
	logger.Println("starting...")

	fatal := func(key string) {
		logger.Fatalf("expected environment variable %q to be set", key)
	}

	addr := ":" + env.Get("PORT").WithDefault("8080")

	// TODO: use public / private key pairs and register them via shared
	// config so that multiple oauth backends can take redirects with each
	// other's login states. (solve key bootstrapping)
	// NOTE: right now this only works with a single oauth backend.

	stateKey, err := oauth.NewKey()
	if err != nil {
		logger.Fatalf("error generating state key: %v", err)
	}

	// Your credentials should be obtained from the Google
	// Developer Console (https://console.developers.google.com).
	h := handler{&oauth.Handler{
		Config: oauth2.Config{
			ClientID:     env.Get("OAUTH_CLIENT_ID").Required(fatal),
			ClientSecret: env.Get("OAUTH_CLIENT_SECRET").Required(fatal),
			RedirectURL:  "https://" + env.Get("DOMAIN").Required(fatal) + "/oauth-google-redirect",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     google.Endpoint,
		},
		StateKey: stateKey,

		// TODO: create a way of sharing cookieKey with multiple
		// backends (maybe public/private).
		// Note: every domain should have a different key. Otherwise it
		// can be copied and used across domains.
		CookieKey: stateKey,

		Domain:     env.Get("DOMAIN").Required(fatal),
		CookieName: "session",
		Service:    "google",
		UserInfo:   "https://openidconnect.googleapis.com/v1/userinfo",
		Log:        logger,
	}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleHome)
	mux.HandleFunc("/login", h.HandleLogin)
	mux.HandleFunc("/oauth-google-redirect", h.HandleRedirect)

	logger.Println("serving on ", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type handler struct {
	*oauth.Handler
}

func (h *handler) handleHome(w http.ResponseWriter, r *http.Request) {
	id, err := h.Cookie(r)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	w.Write(id)
}
