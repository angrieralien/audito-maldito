// auditlog package processes the /var/log/audit/audit.log log file.
// Process records the stream of text and on newline sends the line of text
// to the AuditLogChan for received by the auditd processor for
// correlation and analysis.
package auditlog

import (
	"bufio"
	"context"
	"log"
)

type AuditLogProcessor struct {
	AuditLogChan chan string
}

func (a *AuditLogProcessor) Process(ctx context.Context, r *bufio.Reader) error {
	line, err := r.ReadString('\n')
	if err != nil {
		log.Print("error reading from audit-pipe")
		return err
	}
	a.AuditLogChan <- line
	return nil
}
