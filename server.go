package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("secret_key")

type Register struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[credentials.Username]

	if !ok || expectedPassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(time.Minute * 30)

	claims := &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

}

func Logout(w http.ResponseWriter, r *http.Request){
	var credentials Credentials
	err:= json.NewDecoder(r.Body).Decode(&credentials)
	if err!= nil{
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name: "token",
			Value: "",
			Expires: time.Unix(0,0),
	})

	w.Write([]byte("Logged out"))
}

func Signup(w http.ResponseWriter, r *http.Request){
	var register Register
	err:= json.NewDecoder(r.Body).Decode(&register)
	if err!= nil{
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if register.Username == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Username cannot be empty"))
		return
	}

	if register.Password == ""{
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Password is invalid"))
		return
	}

	if _, exists:= users[register.Username]; exists{
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte("Username already taken"))
		return
	}

	users[register.Username]= register.Password

	w.Write([]byte("Signed up!"))

	//store password
}

func Home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Hello, %s", claims.Username)))

}

