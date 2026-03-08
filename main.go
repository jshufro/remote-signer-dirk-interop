package main

import (
	"flag"
	"log"

	"github.com/jshufro/remote-signer-dirk-interop/config"
)

func main() {
	cfgPath := flag.String("config", "", "Path to config file (optional)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("listen %s:%d, dirk endpoints: %v", cfg.ListenAddress, cfg.ListenPort, cfg.DirkEndpoints)
}
