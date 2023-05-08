// audito-maldito is a daemon that monitors OpenSSH server logins and
// produces structured audit events describing what authenticated users
// did while logged in (e.g., what programs they executed).
package main

import (
	"log"

	"github.com/metal-toolbox/audito-maldito/cmd"
	"github.com/metal-toolbox/audito-maldito/internal/health"
)

func main() {
	appHealth := health.NewHealth()
	if err := cmd.Execute(appHealth); err != nil {
		log.Fatalln("fatal:", err)
	}
}
