package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/zapr"
	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/processors/auditd"
	"github.com/metal-toolbox/audito-maldito/processors/auditlog"

	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

const usage = `audito-maldito

DESCRIPTION
  audito-maldito is a daemon that monitors OpenSSH server logins and
  produces structured audit events describing what authenticated users
  did while logged in (e.g., what programs they executed).

OPTIONS
`

var logger *zap.SugaredLogger

func Run(ctx context.Context, osArgs []string, h *common.Health, optLoggerConfig *zap.Config) error {
	var bootID string
	var auditlogpath string
	var auditLogDirPath string
	logLevel := zapcore.DebugLevel // TODO: Switch default back to zapcore.ErrorLevel.

	flagSet := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flagSet.StringVar(&bootID, "boot-id", "", "Optional Linux boot ID to use when reading from the journal")
	flagSet.StringVar(&auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")
	flagSet.StringVar(&auditLogDirPath, "audit-dir-path", "/var/log/audit", "Path to the Linux audit log directory")
	flagSet.Var(&logLevel, "log-level", "Set the log level according to zapcore.Level")
	flagSet.Usage = func() {
		os.Stderr.WriteString(usage)
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	err := flagSet.Parse(osArgs[1:])
	if err != nil {
		return err
	}

	if optLoggerConfig == nil {
		cfg := zap.NewProductionConfig()
		optLoggerConfig = &cfg
	}

	optLoggerConfig.Level = zap.NewAtomicLevelAt(logLevel)

	l, err := optLoggerConfig.Build()
	if err != nil {
		return err
	}

	defer func() {
		_ = l.Sync() //nolint
	}()

	logger = l.Sugar()

	auditd.SetLogger(logger)

	mid, miderr := common.GetMachineID()
	if miderr != nil {
		return fmt.Errorf("failed to get machine id: %w", miderr)
	}

	nodeName, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		return fmt.Errorf("failed to get node name: %w", nodenameerr)
	}

	eg, groupCtx := errgroup.WithContext(ctx)

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(groupCtx, auditlogpath, zapr.NewLogger(l))
	if auditfileerr != nil {
		return fmt.Errorf("failed to open audit log file: %w", auditfileerr)
	}

	eventWriter := auditevent.NewDefaultAuditEventWriter(auf)
	logins := make(chan common.RemoteUserLogin)

	logger.Infoln("starting workers...")

	auditLogChan := make(chan string)

	eg.Go(func() error {
		auditLogEvents := namedpipe.NamedPipeIngester{
			FilePath: "/var/log/audit/audit-pipe",
		}

		alp := auditlog.AuditLogProcessor{
			AuditLogChan: auditLogChan,
		}

		err := auditLogEvents.Ingest(ctx, alp.Process, logger)
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("audit log ingester exited (%v)", err)
		}
		return err
	})

	sshdEvents := namedpipe.NamedPipeIngester{
		FilePath: "/var/log/audit/journal-pipe",
	}

	sshdProcessor := sshd.NewSshdProcessor(ctx, logins, nodeName, mid, eventWriter)

	eg.Go(func() error {
		err := sshdEvents.Ingest(ctx, sshdProcessor.Process, logger)
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("syslog ingester exited (%v)", err)
		}
		return err
	})

	h.AddReadiness()
	eg.Go(func() error {
		ap := auditd.Auditd{
			Audits: auditLogChan,
			Logins: logins,
			EventW: eventWriter,
			Health: h,
		}

		err := ap.Process(groupCtx)
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("audit worker exited (%v)", err)
		}
		return err
	})

	if err := eg.Wait(); err != nil {
		// We cannot treat errors containing context.Canceled
		// as non-errors because the errgroup.Group uses its
		// own context, which is canceled if one of the Go
		// routines returns a non-nil error. Thus, treating
		// context.Canceled as a graceful shutdown may hide

		// an error returned by one of the Go routines.
		return err
	}

	logger.Infoln("all workers finished without error")

	return nil
}

// lastReadJournalTimeStamp returns the last-read journal entry's timestamp
// or a sensible default if the timestamp cannot be loaded.
func lastReadJournalTimeStamp() uint64 {
	lastRead, err := common.GetLastRead()
	switch {
	case err != nil:
		lastRead = uint64(time.Now().UnixMicro())

		logger.Warnf("failed to read last read timestamp for journal - "+
			"reading from current time (reason: '%s')", err.Error())
	case lastRead == 0:
		lastRead = uint64(time.Now().UnixMicro())

		logger.Info("last read timestamp for journal is zero - " +
			"reading from current time")
	default:
		logger.Infof("last read timestamp for journal is: '%d'", lastRead)
	}

	return lastRead
}
