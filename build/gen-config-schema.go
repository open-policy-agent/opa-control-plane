package main

import (
	"log"
	"os"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s path/to/schema.json", os.Args[0])
	}
	bs, err := config.ReflectSchema()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], bs, 0644); err != nil {
		panic(err)
	}
}
