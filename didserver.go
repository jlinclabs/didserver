package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	_ "github.com/lib/pq"
)

// DB is a global database handle
var DB *sql.DB

// ValidContexts holds enumeration of valid JSON-LD contexts
var ValidContexts = make(map[string]struct{})

// Config holds app configuration data from config.toml
type Config struct {
	Database database
	Keys     keys
}

type database struct {
	ConnectionString string `toml:"connection_string"`
}

type keys struct {
	Public string `toml:"public"`
	Secret string `toml:"secret"`
}

// Conf is a global configuration handle
var Conf Config

// MasterPublicKey can be redefined for testing
var MasterPublicKey string

func main() {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.NoCache)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", indexstr)
	r.Post("/register", registerDID)

	if _, err := toml.DecodeFile("./config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}

	// Get a database connection
	connStr := Conf.Database.ConnectionString
	var err error
	DB, err = sql.Open("postgres", connStr)
	defer DB.Close()
	if err != nil {
		log.Fatal(err)
		return
	}

	// Start the server
	log.Fatal(http.ListenAndServe(":5001", r))
}

// Index page is a json-ld list of API endpoints
func indexstr(w http.ResponseWriter, r *http.Request) {
	MasterPublicKey = Conf.Keys.Public
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"masterPublicKey":%q}`, Conf.Keys.Public)
}
