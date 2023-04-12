package rocky

import (
	"bufio"
	"context"
	"log"
	"regexp"

	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

type RockyProcessor struct {
	SshdProcessor sshd.SshdProcessor
}

func (j *RockyProcessor) Process(ctx context.Context, r *bufio.Reader) error {
	line, err := r.ReadString('\n')
	if err != nil {
		log.Print("error reading from audit-pipe")
		return err
	}
	sm := j.ParseRockySecureMessage(line)
	err = j.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
	return err
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
