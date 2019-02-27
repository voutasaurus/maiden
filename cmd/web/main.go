package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/voutasaurus/env"
	"github.com/voutasaurus/oauth"
)

var errNotAllowed = errors.New("email not allowed")

func main() {
	logger := log.New(os.Stderr, "oauthtest: ", log.Llongfile|log.LstdFlags|log.LUTC)
	logger.Println("starting...")

	debugLogFiles(logger)

	fatal := func(key string) {
		logger.Fatalf("expected environment variable %q to be set", key)
	}

	addr := ":" + env.Get("PORT").WithDefault("8080")
	allowedList := env.Get("ACL").List(",")
	allowed := func(email string) bool {
		for _, e := range allowedList {
			if email == e {
				return true
			}
		}
		return false
	}

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

		ACL: func(p *oauth.Profile) error {
			if !allowed(p.Email) {
				return errNotAllowed
			}
			return nil
		},

		Domain:     env.Get("DOMAIN").Required(fatal),
		CookieName: "session",
		Service:    "google",
		UserInfo:   "https://openidconnect.googleapis.com/v1/userinfo",
		Log:        logger,
	}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.auth(h.handleHome))
	mux.HandleFunc("/login", h.HandleLogin)
	mux.HandleFunc("/oauth-google-redirect", h.HandleRedirect)

	mux.HandleFunc("/static/", h.auth(h.handleStatic))
	mux.HandleFunc("/invite", redirect("/static/html/invite.html"))

	logger.Println("serving on ", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type handler struct {
	*oauth.Handler
}

func (h *handler) handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, id(r))
}

func (h *handler) handleStatic(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("serving: %v", r.URL.Path)
	http.ServeFile(w, r, r.URL.Path)
}

const authHeaderKey = "X-AuthID"

func (h *handler) auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := h.Cookie(r)
		if err != nil {
			http.Error(w, err.Error(), 401)
			return
		}
		r.Header.Add(authHeaderKey, string(id))
		fn(w, r)
	}
}

func id(r *http.Request) string {
	return r.Header.Get(authHeaderKey)
}

func redirect(url string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, url, 302)
	}
}

func debugLogFiles(lg *log.Logger) {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		lg.Fatal(err)
	}

	for _, f := range files {
		lg.Printf("found file: %v", f.Name())
	}
}
