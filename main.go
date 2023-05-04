// audito-maldito is a daemon that monitors OpenSSH server logins and
// produces structured audit events describing what authenticated users
// did while logged in (e.g., what programs they executed).
package main

import (
	"log"

	"github.com/metal-toolbox/audito-maldito/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatalln("fatal:", err)
	}
}
