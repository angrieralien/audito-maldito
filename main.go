// audito-maldito is a daemon that monitors OpenSSH server logins and
// produces structured audit events describing what authenticated users
// did while logged in (e.g., what programs they executed).
package main

import (
	"github.com/metal-toolbox/audito-maldito/cmd"
)

func main() {
	cmd.Execute()
}
