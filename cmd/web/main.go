package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/voutasaurus/env"
	"github.com/voutasaurus/oauth"
)

var errNotAllowed = errors.New("email not allowed")

func main() {
	logger := log.New(os.Stderr, "maiden: ", log.Llongfile|log.LstdFlags|log.LUTC)
	logger.Println("starting...")

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
	admin := handler{&oauth.Handler{
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

		FinalizeLogin: func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/invite", 307)
		},

		Domain:     env.Get("DOMAIN").Required(fatal),
		CookieName: "session",
		Service:    "google",
		UserInfo:   "https://openidconnect.googleapis.com/v1/userinfo",
		Log:        logger,
	}}

	m := &mailer{
		// TODO: use other shared key
		key: stateKey,
		url: "https://" + admin.Domain + "/verify/",
		log: logger,
		user: &oauth.Handler{
			CookieKey:  stateKey,
			Domain:     admin.Domain,
			CookieName: "usession",
		},
		mail: mailConn{
			host: addrToHost(env.Get("MAILSERVER_ADDR").Required(fatal)),
			port: addrToPort(env.Get("MAILSERVER_ADDR").Required(fatal)),
			from: env.Get("MAILFROM").Required(fatal),
			pass: env.Get("MAILPASS").Required(fatal),
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", admin.handleHome)
	mux.HandleFunc("/login", admin.HandleLogin)
	mux.HandleFunc("/oauth-google-redirect", admin.HandleRedirect)

	mux.HandleFunc("/static/", admin.auth(admin.handleStatic))
	mux.HandleFunc("/invite", admin.auth(serveFile("static/html/invite.html")))
	mux.HandleFunc("/invited", admin.auth(m.handleEmailPost))

	mux.HandleFunc("/verify/", m.handleVerify)
	mux.HandleFunc("/password", m.auth(serveFile("static/html/password.html")))
	mux.HandleFunc("/passworded", m.auth(m.handlePasswordPost))

	logger.Println("serving on ", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type handler struct {
	*oauth.Handler
}

func (h *handler) handleHome(w http.ResponseWriter, r *http.Request) {
	_, err := h.Cookie(r)
	if err != nil {
		http.ServeFile(w, r, "static/html/preauth.html")
		return
	}
	// TODO: proper html template (insert id or email somewhere on the page
	// to signal to the user that they are authenticated)
	http.ServeFile(w, r, "static/html/invite.html")
}

func (h *handler) handleStatic(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, r.URL.Path[1:])
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

func serveFile(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filename)
	}
}

// Mailer

type mailer struct {
	key *[32]byte
	log *log.Logger
	url string

	// For user authentication after email verification
	user *oauth.Handler

	mail mailConn
}

var errTokenExpired = errors.New("token expired after 24hrs")

func encrypt(key *[32]byte, msg string) (string, error) {
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().UnixNano()))
	b, err := oauth.EncryptBytes(key, append(ts, msg...))
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func decrypt(key *[32]byte, tok string) (string, error) {
	tb, err := base64.URLEncoding.DecodeString(tok)
	if err != nil {
		return "", err
	}
	b, err := oauth.DecryptBytes(key, tb)
	if err != nil {
		return "", err
	}
	expiry := time.Unix(0, int64(binary.LittleEndian.Uint64(b[:8]))).Add(24 * time.Hour)
	if expiry.Before(time.Now()) {
		return "", errTokenExpired
	}
	msg := string(b[8:])
	return msg, nil
}

func (m *mailer) handleEmailPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.Form.Get("email")
	if !validEmail(email) {
		http.Error(w, "invalid email address", 400)
		return
	}
	if err := m.invite(email); err != nil {
		http.Error(w, err.Error(), 500)
	}
	http.ServeFile(w, r, "static/html/invited.html")
}

func validEmail(e string) bool {
	// TODO: check email address
	// TODO: also do basic validation client side in JS
	return true
}

func (m *mailer) invite(email string) error {
	m.log.Println("inviting email:", email)
	tok, err := encrypt(m.key, email)
	if err != nil {
		return err
	}
	return m.send(email, m.url+tok)
}

func (m *mailer) handleVerify(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Path[len("/verify/"):]
	m.log.Printf("verifying %q", tok)
	email, err := decrypt(m.key, tok)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	if err := verify(email); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	m.user.SetCookie(w, []byte(email))
	http.Redirect(w, r, "/password", 307)
	m.log.Printf("verified: %q", email)
}

func verify(email string) error {
	// TODO: mark email as verified in storage?
	return nil
}

func (m *mailer) auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := m.user.Cookie(r)
		if err != nil {
			http.Error(w, err.Error(), 401)
			return
		}
		r.Header.Add(authHeaderKey, string(id))
		fn(w, r)
	}
}

func (m *mailer) handlePasswordPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := id(r)
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	confirm := r.Form.Get("confirm")
	if password != confirm {
		// TODO: add check client side
		http.Error(w, "password not equal to confirm", 500)
		return
	}
	if err := m.setUser(email, username, password); err != nil {
		http.Error(w, "error setting user", 500)
	}
	http.ServeFile(w, r, "static/html/passworded.html")
}

func (m *mailer) setUser(email, username, password string) error {
	m.log.Printf("%q is setting username=%q, password=%v", email, username, password != "")
	// TODO: update storage with user details (hash password)
	return nil
}
