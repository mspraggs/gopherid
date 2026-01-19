package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
)

var (
	// Server State
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	publicKeyBytes []byte // The raw PKIX bytes (The "Secret")
	// Map[Username]MFA_Secret_String
	// We use sync.Map for memory safety, but the LOGIC is still racy.
	mfaStore sync.Map
	flag     = func() string {
		f, err := os.Open("flag.txt")
		if err != nil {
			panic(err)
		}
		defer f.Close()

		bs, err := io.ReadAll(f)
		if err != nil {
			panic(err)
		}

		return string(bs)
	}()
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func main() {
	if flag == "" {
		panic("Flag not configured")
	}

	setupKeys()

	// Static & OpenAPI
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)
	http.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "openapi.json")
	})

	// API
	http.HandleFunc("/api/login", LoginHandler)
	http.HandleFunc("/api/mfa/setup", AuthMiddleware(MFASetupHandler))
	http.HandleFunc("/api/flag", AuthMiddleware(FlagHandler))

	// Standard JWKS Endpoint
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Token", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {

			// If alg is HS256, we use the Public Key BYTES as the HMAC secret.
			if token.Method.Alg() == "HS256" {
				return publicKeyBytes, nil
			}

			// Normal RS256 validation
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return publicKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, `{"message":"Invalid Token"}`, http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = setClaims(ctx, token.Claims.(*Claims))
		next(w, r.WithContext(ctx))
	}
}

// -- HANDLERS --

func MFASetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	claims := getClaims(r.Context())

	// 1. Set "Pending" State (The Trap)
	// We use a known string as the secret temporarily.
	// Note: Base32 requires specific charset, so we use a valid Base32 string.
	// "MFAINITPENDING" is valid base32 (letters A-Z, numbers 2-7).
	tempSecret := "MFAINITPENDING23"
	mfaStore.Store(claims.Username, tempSecret)

	// Simulate "Generating Secure Crypto Keys"
	time.Sleep(800 * time.Millisecond)

	// 3. Generate Real Secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GopherID",
		AccountName: claims.Username,
	})
	if err != nil {
		http.Error(w, `{"message": "Crypto Error"}`, http.StatusInternalServerError)
		return
	}

	// 4. Overwrite with Real Secret
	mfaStore.Store(claims.Username, key.Secret())

	// Return the URL so the Frontend can generate a QR Code
	newSecret := rand.Text()
	json.NewEncoder(w).Encode(map[string]string{
		"message": "MFA Setup Complete",
		"secret":  newSecret,
		"url":     strings.ReplaceAll(key.URL(), key.Secret(), newSecret),
	})
}

func FlagHandler(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r.Context())

	// 1. JWT Check (Bypassed via Key Confusion)
	if claims.Role != "admin" {
		http.Error(w, `{"message":"Forbidden: Admins only"}`, http.StatusForbidden)
		return
	}

	// 2. MFA Check
	// Retrieve the user's secret from memory
	val, ok := mfaStore.Load(claims.Username)
	if !ok {
		http.Error(w, `{"message":"MFA Not Setup. Please configure 2FA."}`, http.StatusForbidden)
		return
	}
	secret := val.(string)

	// Get the user's code from the Header
	userCode := r.Header.Get("X-MFA-Code")
	if userCode == "" {
		http.Error(w, `{"message":"Missing X-MFA-Code header"}`, http.StatusUnauthorized)
		return
	}

	// Validate TOTP
	// If hit during race window, secret is "MFAINITPENDING"
	valid := totp.Validate(userCode, secret)

	if !valid {
		http.Error(w, `{"message":"Invalid MFA Code"}`, http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": flag})
}

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	// Convert RSA key parts to JWKS format (Base64URL encoded Big Ints)
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

	// E is an int, usually 65537. Needs to be bytes.
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(publicKey.E))
	// Trim leading zeros for strict JWKS compliance
	eBytes = trimLeadingZeros(eBytes)
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Kid: "gopher-key-1",
				Use: "sig",
				Alg: "RS256",
				N:   n,
				E:   e,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"message":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var creds LoginRequest
	// We try to decode JSON body
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, `{"message":"Invalid request format"}`, http.StatusBadRequest)
		return
	}

	// Logic Hint: You cannot simply "log in" as admin.
	if creds.Username == "admin" {
		http.Error(w, `{"message":"Admin login is restricted to internal consoles only."}`, http.StatusForbidden)
		return
	}

	// For any other user, we grant a "user" role token
	expirationTime := time.Now().Add(15 * time.Minute)

	// Use the provided username in the claims so the UI looks personalized
	if creds.Username == "" {
		creds.Username = "guest"
	}

	claims := &Claims{
		Username: creds.Username,
		Role:     "user", // Hardcoded to user!
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "gopher-key-1"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, `{"message":"Signing Error"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// -- HELPERS --

func setupKeys() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publicKey = &privateKey.PublicKey

	// The "Secret" used for the exploit is the PEM/PKIX encoded public key
	pubASN1, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicKeyBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
}

func trimLeadingZeros(b []byte) []byte {
	for i, v := range b {
		if v != 0 {
			return b[i:]
		}
	}
	return []byte{0}
}

// Context helpers (simplified)
func setClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, "props", claims)
}
func getClaims(ctx context.Context) *Claims {
	return ctx.Value("props").(*Claims)
}
