package journald

import (
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

type JournaldProcessor struct {
	SshdProcessor sshd.SshdProcessor
}

func (j *JournaldProcessor) Process(ctx context.Context, r io.Reader, currentLog *bytes.Buffer, buf []byte) (int, error) {
	n, err := r.Read(buf[:cap(buf)])
	sp := strings.Split(string(buf[:n]), "\n")

	if len(sp) > 1 {
		sm := j.ParseSyslogMessage(currentLog.String() + sp[0])
		j.SshdProcessor.ProcessEntry(ctx, sm)
		for _, line := range sp[1 : len(sp)-1] {
			sm := j.ParseSyslogMessage(line)
			j.SshdProcessor.ProcessEntry(ctx, sm)
		}
		currentLog.Truncate(0)
		currentLog.WriteString(sp[len(sp)-1])

	} else {
		currentLog.Write(buf[:n])
	}
	return n, err
}

func (s *JournaldProcessor) ParseSyslogMessage(entry string) sshd.SyslogMessage {
	entrySplit := strings.Split(entry, " ")
	pid := entrySplit[0]
	logMsg := strings.Join(entrySplit[1:], " ")
	logMsg = strings.TrimLeft(logMsg, " ")
	return sshd.SyslogMessage{PID: pid, Message: logMsg}
}
