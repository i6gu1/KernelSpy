// Package handler is the Vercel Go serverless function entry point.
//
// Vercel requires api/*.go files to declare `package handler` and export a
// `Handler(w http.ResponseWriter, r *http.Request)` function. The entire app
// (pages, static assets and JSON API) is served through this single function;
// vercel.json rewrites every route to /api/handler.
package handler

import (
	"net/http"

	"black-hat/handlers"
)

// appHandler is built once and reused for every request. Building the mux
// inside Handler() would re-create it per invocation, which is wasteful on a
// serverless runtime where every request flows through this function.
var appHandler = handlers.NewHandler()

// Handler is the exported serverless function. All requests are handled by the
// shared app handler used by main.go, so local development and Vercel behave
// identically.
func Handler(w http.ResponseWriter, r *http.Request) {
	appHandler.ServeHTTP(w, r)
}
