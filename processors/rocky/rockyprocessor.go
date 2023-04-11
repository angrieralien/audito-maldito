package rocky

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"

	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

type RockyProcessor struct {
	SshdProcessor sshd.SshdProcessor
}

func (j *RockyProcessor) Process(ctx context.Context, r io.Reader, currentLog *bytes.Buffer, buf []byte) (int, error) {
	n, err := r.Read(buf[:cap(buf)])
	sp := strings.Split(string(buf[:n]), "\n")

	if len(sp) > 1 {
		sm := j.ParseRockySecureMessage(currentLog.String() + sp[0])
		j.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
		for _, line := range sp[1 : len(sp)-1] {
			sm := j.ParseRockySecureMessage(line)
			j.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
		}
		currentLog.Truncate(0)
		currentLog.WriteString(sp[len(sp)-1])

	} else {
		currentLog.Write(buf[:n])
	}
	return n, err
}

// pidRE regex matches a sshd log line extracting the procid and message into a match group
// example log line:
//
//	Apr  3 15:48:03 localhost sshd[3894]: Connection closed by authenticating user user 127.0.0.1 port 41796 [preauth]
//
// regex match:
//
//	entryMatches[0]: sshd[3894]: Connection closed by authenticating user user 127.0.0.1 port 41796 [preauth]
//	entryMatches[1]: 3894
//	entryMatches[2]: Connection closed by authenticating user user 127.0.0.1 port 41796 [preauth]
var pidRE = regexp.MustCompile(`sshd\[(?P<PROCID>\w+)\]: (?P<MSG>.+)`)

// numberOfMatches should have 3 match groups.
var numberOfMatches = 3

func (r *RockyProcessor) ParseRockySecureMessage(line string) sshd.SshdLogEntry {
	messageMatches := pidRE.FindStringSubmatch(line)
	if messageMatches == nil {
		return sshd.SshdLogEntry{}
	}

	if len(messageMatches) < numberOfMatches {
		return sshd.SshdLogEntry{}
	}

	return sshd.SshdLogEntry{PID: messageMatches[1], Message: messageMatches[2]}
}
