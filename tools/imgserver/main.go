// imgserver is a throwaway static file server used to preview the "ui pic"
// design-reference folders in a browser. Serves the root folder listing too.
package main

import (
	"log"
	"net/http"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir(".")))
	log.Println("imgserver listening on :8766")
	log.Fatal(http.ListenAndServe(":8766", nil))
}
