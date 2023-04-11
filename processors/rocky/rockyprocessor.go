package rocky

import (
	"context"
	"fmt"
	"regexp"
)

type RockyProcessor struct{}

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

func (r *RockyProcessor) Process(ctx context.Context, line string) (string, error) {
	entryMatches := pidRE.FindStringSubmatch(line)
	if entryMatches == nil {
		return "", nil
	}

	if len(entryMatches) < numberOfMatches {
		return "", fmt.Errorf("match group less than 3")
	}

	return fmt.Sprintf("%s %s", entryMatches[1], entryMatches[2]), nil
}
