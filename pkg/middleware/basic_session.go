package middleware

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/justinas/alice"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

func NewBasicAuthSessionLoader(htpasswdFile string) (alice.Constructor, error) {
	htpasswd, err := newHtpasswdFromFile(htpasswdFile)
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		return loadBasicAuthSession(htpasswd, next)
	}, nil
}

// loadBasicAuthSession attmepts to load a session from basic auth credentials
// stored in an Authorization header within the request.
// If no authorization header is found, or the header is invalid, no session
// will be loaded and the request will be passed to the next handler.
// If a session was loaded by a previous handler, it will not be replaced.
func loadBasicAuthSession(htpasswd *htpasswdMap, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := getBasicSession(htpasswd, req)
		if err != nil {
			logger.Printf("Error retrieving session from token in Authorization header: %v", err)
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getBasicSession attempts to load a basic session from the request.
// If the credentials in the request exist within the htpasswdMap,
// a new session will be created.
func getBasicSession(htpasswd *htpasswdMap, req *http.Request) (*sessionsapi.SessionState, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		// No auth header provided, so don't attempt to load a session
		return nil, nil
	}

	user, password, err := findBasicCredentialsFromHeader(auth)
	if err != nil {
		return nil, err
	}

	if htpasswd.Validate(user, password) {
		logger.PrintAuthf(user, req, logger.AuthSuccess, "Authenticated via basic auth and HTpasswd File")
		return &sessionsapi.SessionState{User: user}, nil
	}

	logger.PrintAuthf(user, req, logger.AuthFailure, "Invalid authentication via basic auth: not in Htpasswd File")
	return nil, nil
}

// findBasicCredentialsFromHeader finds basic auth credneitals from the
// Authorization header of a given request.
func findBasicCredentialsFromHeader(header string) (string, string, error) {
	tokenType, token, err := splitAuthHeader(header)
	if err != nil {
		return "", "", err
	}

	if tokenType != "Basic" {
		return "", "", fmt.Errorf("invalid Authorization header: %q", header)
	}

	user, password, err := getBasicAuthCredentials(token)
	if err != nil {
		return "", "", fmt.Errorf("error decoding basic auth credentials: %v", err)
	}

	return user, password, nil
}

// htpasswdMap represents the structure of an htpasswd file.
// Passwords must be generated with -B for bcrypt or -s for SHA1.
type htpasswdMap struct {
	Users map[string]string
}

// newHtpasswdFromFile constructs an httpasswdMap from the file at the path given.
func newHtpasswdFromFile(path string) (*htpasswdMap, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open htpasswd file: %v", err)
	}
	defer r.Close()
	return newHtpasswd(r)
}

// newHtpasswd consctructs an htpasswd from an io.Reader (an opened file).
func newHtpasswd(file io.Reader) (*htpasswdMap, error) {
	csvReader := csv.NewReader(file)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("could not read htpasswd file: %v", err)
	}
	h := &htpasswdMap{Users: make(map[string]string)}
	for _, record := range records {
		h.Users[record[0]] = record[1]
	}
	return h, nil
}

// Validate checks a users password against the htpasswd entries
func (h *htpasswdMap) Validate(user string, password string) bool {
	realPassword, exists := h.Users[user]
	if !exists {
		return false
	}

	shaPrefix := realPassword[:5]
	if shaPrefix == "{SHA}" {
		shaValue := realPassword[5:]
		d := sha1.New()
		d.Write([]byte(password))
		return shaValue == base64.StdEncoding.EncodeToString(d.Sum(nil))
	}

	bcryptPrefix := realPassword[:4]
	if bcryptPrefix == "$2a$" || bcryptPrefix == "$2b$" || bcryptPrefix == "$2x$" || bcryptPrefix == "$2y$" {
		return bcrypt.CompareHashAndPassword([]byte(realPassword), []byte(password)) == nil
	}

	logger.Printf("Invalid htpasswd entry for %s. Must be a SHA or bcrypt entry.", user)
	return false
}
