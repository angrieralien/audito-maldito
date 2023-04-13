package syslog

import (
	"bufio"
	"context"
	"log"
	"strings"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"

	"go.uber.org/zap"
)

type SyslogIngester struct {
	namedpipe.NamedPipeIngester
	SshdProcessor sshd.SshdProcessor
	Logger        *zap.SugaredLogger
}

func (s *SyslogIngester) Process(ctx context.Context, r *bufio.Reader) error {
	s.Logger.Infof("started: Reading string in JouraldProcessor")
	line, err := r.ReadString('\n')
	s.Logger.Infof("finished: Reading string in JouraldProcessor")
	if err != nil {
		log.Print("error reading from audit-pipe")
		return err
	}
	sm := s.ParseSyslogMessage(line)
	err = s.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
	return err
}

func (s *SyslogIngester) ParseSyslogMessage(entry string) sshd.SshdLogEntry {
	entrySplit := strings.Split(entry, " ")
	pid := entrySplit[0]
	logMsg := strings.Join(entrySplit[1:], " ")
	logMsg = strings.TrimLeft(logMsg, " ")
	return sshd.SshdLogEntry{PID: pid, Message: logMsg}
}
