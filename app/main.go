package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = "app"
	clientSecret = "dR2b1PuRH0OrZHqF1QotF0i604AuaNXx"
)

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://localhost:8080/auth/realms/demo")
	if err != nil {
		log.Fatal(err)
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:3000/auth/redirect",
		Scopes:       []string{oidc.ScopeOpenID, "roles", "profile", "email"},
	}

	state := "dontfoolme"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/redirect", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "State does not match!", http.StatusBadRequest)
			return
		}

		OAuth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Error while swapping token", http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := OAuth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "Error while retrieving Token ID", http.StatusInternalServerError)
			return
		}

		res := struct {
			OAuth2Token *oauth2.Token;
			IDToken string;
		} {
			OAuth2Token, rawIDToken,
		}

		data, _ := json.MarshalIndent(res, "", "   ")
		w.Write(data)
	})

	log.Fatal(http.ListenAndServe(":3000", nil))
}
