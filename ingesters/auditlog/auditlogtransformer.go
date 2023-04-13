// auditlog package processes the /var/log/audit/audit.log log file.
// Process records the stream of text and on newline sends the line of text
// to the AuditLogChan for received by the auditd processor for
// correlation and analysis.
package auditlog

import (
	"bufio"
	"context"
	"log"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"go.uber.org/zap"
)

type AuditLogIngester struct {
	namedpipe.NamedPipeIngester
	AuditLogChan chan string
	Logger       *zap.SugaredLogger
}

func (a *AuditLogIngester) Process(ctx context.Context, r *bufio.Reader) error {
	a.Logger.Infof("started: Reading string in AuditLogProcessor")
	line, err := r.ReadString('\n')
	a.Logger.Info("here is the line %s", line)
	a.Logger.Infof("finished: Reading string in AuditLogProcessor")
	if err != nil {
		log.Print("error reading from audit-pipe")
		return err
	}
	a.AuditLogChan <- line
	return nil
}
