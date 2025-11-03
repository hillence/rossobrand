package main

import (
	"log"
	"os"

	"gogo/database"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// Default to local postgres started in this workspace (unix socket in /tmp)
		os.Setenv("DATABASE_URL", "postgres://user:password@/gogo?host=/tmp&port=5433&sslmode=disable")
	}

	if err := database.Connect(); err != nil {
		log.Fatal(err)
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		log.Fatal(err)
	}
}
