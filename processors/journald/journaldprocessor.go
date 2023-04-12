package journald

import (
	"bufio"
	"context"
	"log"
	"strings"

	"github.com/metal-toolbox/audito-maldito/processors/sshd"
	"go.uber.org/zap"
)

type JournaldProcessor struct {
	SshdProcessor sshd.SshdProcessor
	Logger        *zap.SugaredLogger
}

func (j *JournaldProcessor) Process(ctx context.Context, r *bufio.Reader) error {
	j.Logger.Infof("started: Reading string in JouraldProcessor")
	line, err := r.ReadString('\n')
	j.Logger.Infof("finished: Reading string in JouraldProcessor")
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
