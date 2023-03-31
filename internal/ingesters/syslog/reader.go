package syslog

import (
	"context"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/audito-maldito/internal/common"
)

type Syslog struct {
	NodeName  string
	MachineID string
	//	onMessage func(syslogLine string) error
	Logins chan common.RemoteUserLogin
	EventW *auditevent.EventWriter
}

func (s *Syslog) NewLine(ctx context.Context, entryMsg string, pid string) error {
	return processEntry(&processEntryConfig{
		ctx:       ctx,
		logins:    s.Logins,
		logEntry:  entryMsg,
		nodeName:  s.NodeName,
		machineID: s.MachineID,
		when:      time.Now(),
		pid:       pid,
		eventW:    s.EventW,
	})
}
