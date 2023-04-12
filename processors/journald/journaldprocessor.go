package journald

import (
	"bufio"
	"context"
	"log"
	"strings"

	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

type JournaldProcessor struct {
	SshdProcessor sshd.SshdProcessor
}

func (j *JournaldProcessor) Process(ctx context.Context, r *bufio.Reader) error {
	line, err := r.ReadString('\n')
	if err != nil {
		log.Print("error reading from audit-pipe")
		return err
	}
	sm := j.ParseSyslogMessage(line)
	err = j.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
	return err
}

func (s *JournaldProcessor) ParseSyslogMessage(entry string) sshd.SshdLogEntry {
	entrySplit := strings.Split(entry, " ")
	pid := entrySplit[0]
	logMsg := strings.Join(entrySplit[1:], " ")
	logMsg = strings.TrimLeft(logMsg, " ")
	return sshd.SshdLogEntry{PID: pid, Message: logMsg}
}
