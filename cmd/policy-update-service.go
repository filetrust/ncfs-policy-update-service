package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	policy "github.com/filetrust/policy-update-service/pkg"
	"github.com/golang/gddo/httputil/header"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shaj13/go-guardian/auth"
	"github.com/shaj13/go-guardian/auth/strategies/basic"
	"github.com/shaj13/go-guardian/auth/strategies/bearer"
	"github.com/shaj13/go-guardian/store"
	"github.com/urfave/negroni"
)

const (
	ok           = "ok"
	usererr      = "user_error"
	jwterr       = "jwt_error"
	jsonerr      = "json_error"
	k8sclient    = "k8s_client_error"
	configmaperr = "configmap_error"
)

var (
	tokenProcTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gw_ncfspolicyupdate_tokenrequest_processing_time_millisecond",
			Help:    "Time taken to process token creation request",
			Buckets: []float64{5, 10, 100, 250, 500, 1000},
		},
	)

	tokenReqTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gw_ncfspolicyupdate_tokenrequest_received_total",
			Help: "Number of token creation requests received",
		},
		[]string{"status"},
	)

	policyUpdateProcTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gw_ncfspolicyupdate_updaterequest_processing_time_millisecond",
			Help:    "Time taken to process policy update request",
			Buckets: []float64{5, 10, 100, 250, 500, 1000},
		},
	)

	policyUpdateReqTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gw_ncfspolicyupdate_updaterequest_received_total",
			Help: "Number of policy update requests received",
		},
		[]string{"status"},
	)

	authProcTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gw_ncfspolicyupdate_authenticate_processing_time_millisecond",
			Help:    "Time taken to authenticate the request",
			Buckets: []float64{5, 10, 100, 250, 500, 1000},
		},
	)

	authReqTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gw_ncfspolicyupdate_authenticate_received_total",
			Help: "Number of authenticatations received",
		},
		[]string{"status"},
	)

	listeningPort = os.Getenv("LISTENING_PORT")
	namespace     = os.Getenv("NAMESPACE")
	configmapName = os.Getenv("CONFIGMAP_NAME")
	username      = os.Getenv("USERNAME")
	password      = os.Getenv("PASSWORD")

	authenticator auth.Authenticator
	cache         store.Cache
)

type Policy struct {
	UnprocessableFileTypeAction *int
	GlasswallBlockedFilesAction *int
}

func updatePolicy(w http.ResponseWriter, r *http.Request) {
	defer func(start time.Time) {
		policyUpdateProcTime.Observe(float64(time.Since(start).Milliseconds()))
	}(time.Now())

	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Expose-Headers", "*")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
			msg := "Content-Type header is not application/json"
			http.Error(w, msg, http.StatusUnsupportedMediaType)
			return
		}
	}

	// enforce body size limit
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)

	// enforce body properties
	dec.DisallowUnknownFields()

	var p Policy
	err := dec.Decode(&p)
	if err != nil {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		http.Error(w, err.Error(), http.StatusBadRequest)
		switch {
		case errors.As(err, &syntaxError):
			msg := fmt.Sprintf("Request body contains badly-formed JSON (at position %d)", syntaxError.Offset)
			http.Error(w, msg, http.StatusBadRequest)
		case errors.Is(err, io.ErrUnexpectedEOF):
			msg := fmt.Sprintf("Request body contains badly-formed JSON")
			http.Error(w, msg, http.StatusBadRequest)
		case errors.As(err, &unmarshalTypeError):
			msg := fmt.Sprintf("Request body contains an invalid value for the %q field (at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)
			http.Error(w, msg, http.StatusBadRequest)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			msg := fmt.Sprintf("Request body contains unknown field %s", fieldName)
			http.Error(w, msg, http.StatusBadRequest)
		case errors.Is(err, io.EOF):
			msg := "Request body must not be empty"
			http.Error(w, msg, http.StatusBadRequest)
		case err.Error() == "http: request body too large":
			msg := "Request body must not be larger than 1MB"
			http.Error(w, msg, http.StatusRequestEntityTooLarge)
		default:
			log.Println(err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

	if p.UnprocessableFileTypeAction == nil {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
		http.Error(w, "UnprocessableFileTypeAction is required.", http.StatusBadRequest)
		return
	}

	if *p.UnprocessableFileTypeAction <= 0 || *p.UnprocessableFileTypeAction >= 5 {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
		http.Error(w, "UnprocessableFileTypeAction must be between 1-4 inclusive.", http.StatusBadRequest)
		return
	}

	if p.GlasswallBlockedFilesAction == nil {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
		http.Error(w, "GlasswallBlockedFilesAction is required.", http.StatusBadRequest)
		return
	}

	if *p.GlasswallBlockedFilesAction <= 0 || *p.GlasswallBlockedFilesAction >= 5 {
		policyUpdateReqTotal.WithLabelValues(jsonerr).Inc()
		http.Error(w, "GlasswallBlockedFilesAction  must be between 1-4 inclusive.", http.StatusBadRequest)
		return
	}

	b := bytes.Buffer{}
	enc := json.NewEncoder(&b)
	enc.Encode(p)
	str := string(b.Bytes())

	args := policy.PolicyArgs{
		Policy:        str,
		Namespace:     namespace,
		ConfigMapName: configmapName,
	}

	err = args.GetClient()
	if err != nil {
		policyUpdateReqTotal.WithLabelValues(k8sclient).Inc()
		log.Printf("Unable to get client: %v", err)
		http.Error(w, "Something went wrong getting K8 Client.", http.StatusInternalServerError)
		return
	}

	err = args.UpdatePolicy()
	if err != nil {
		policyUpdateReqTotal.WithLabelValues(configmaperr).Inc()
		log.Printf("Unable to update policy: %v", err)
		http.Error(w, "Something went wrong when updating the config map.", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Successfully updated config map."))
	policyUpdateReqTotal.WithLabelValues(ok).Inc()
}

func createToken(w http.ResponseWriter, r *http.Request) {
	defer func(start time.Time) {
		tokenProcTime.Observe(float64(time.Since(start).Milliseconds()))
	}(time.Now())

	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Expose-Headers", "*")

	if r.Method == "OPTIONS" {
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "auth-app",
		"sub": username,
		"aud": "any",
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})
	jwtToken, _ := token.SignedString([]byte("secret"))
	w.Write([]byte(jwtToken))
	tokenReqTotal.WithLabelValues(ok).Inc()
}

func validateUser(ctx context.Context, r *http.Request, usr, pass string) (auth.Info, error) {
	if usr == username && pass == password {
		return auth.NewDefaultUser(usr, "1", nil, nil), nil
	}

	authReqTotal.WithLabelValues(usererr).Inc()
	return nil, fmt.Errorf("Invalid credentials")
}

func verifyToken(ctx context.Context, r *http.Request, tokenString string) (auth.Info, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			authReqTotal.WithLabelValues(jwterr).Inc()
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})

	if err != nil {
		authReqTotal.WithLabelValues(jwterr).Inc()
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		user := auth.NewDefaultUser(claims["sub"].(string), "", nil, nil)
		return user, nil
	}

	authReqTotal.WithLabelValues(jwterr).Inc()
	return nil, fmt.Errorf("Invalid token")
}

func authMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func(start time.Time) {
		authProcTime.Observe(float64(time.Since(start).Milliseconds()))
	}(time.Now())

	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Expose-Headers", "*")

	if r.Method == "OPTIONS" {
		return
	}
	log.Println("Executing Auth Middleware")
	user, err := authenticator.Authenticate(r)
	if err != nil {
		code := http.StatusUnauthorized
		http.Error(w, err.Error(), code)
		return
	}

	authReqTotal.WithLabelValues(ok).Inc()
	log.Printf("User %s Authenticated\n", user.UserName())
	next.ServeHTTP(w, r)
}

func setupGoGuardian() {
	authenticator = auth.New()
	cache = store.NewFIFO(context.Background(), time.Minute*10)

	basicStrategy := basic.New(validateUser, cache)
	tokenStrategy := bearer.New(verifyToken, cache)

	authenticator.EnableStrategy(basic.StrategyKey, basicStrategy)
	authenticator.EnableStrategy(bearer.CachedStrategyKey, tokenStrategy)
}

func main() {
	if listeningPort == "" || namespace == "" || configmapName == "" || username == "" || password == "" {
		log.Fatalf("init failed: LISTENTING_PORT, NAMESPACE, CONFIGMAP_NAME, USERNAME or PASSWORD environment variables not set")
	}

	log.Printf("Listening on port with TLS :%v", listeningPort)

	setupGoGuardian()
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/auth/token", createToken).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/v1/policy", updatePolicy).Methods("PUT", "OPTIONS")

	n := negroni.New()
	n.Use(negroni.NewRecovery())
	n.Use(negroni.NewLogger())
	n.Use(negroni.HandlerFunc(authMiddleware))
	n.UseHandler(router)

	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%v", listeningPort), "/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key", n))
}
