package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/zapr"
	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/ingesters/auditlog"
	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/ingesters/rocky"
	"github.com/metal-toolbox/audito-maldito/ingesters/syslog"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
	"github.com/metal-toolbox/audito-maldito/internal/util"
	"github.com/metal-toolbox/audito-maldito/processors/auditd"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

var (
	appEventsOutput   string
	auditdLogFilePath string
	sshdLogFilePath   string
	metricsCfg        metricsConfig
)

var namedpipeCmd = &cobra.Command{
	Use:   "journald",
	Short: "Uses coreos/go-systemd code to access journald for data ingestion.",
	Long: `Uses coreos/go-systemd code to access journald for data ingestion.
	 Processes sshd logs and audit events.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := RunNamedPipe(ctx, config, health.NewHealth(), nil); err != nil {
			log.Fatalln("fatal:", err)
		}
	},
}

func init() {
	namedpipeCmd.PersistentFlags().StringVar(
		&appEventsOutput,
		"app-events-output",
		"/app-audit/app-events-output.log",
		"Path to the app events output")
	namedpipeCmd.PersistentFlags().StringVar(
		&sshdLogFilePath,
		"sshd-log-file-path",
		"/app/audit/sshd-pipe",
		"Path to the sshd log file")
	namedpipeCmd.PersistentFlags().StringVar(
		&auditdLogFilePath,
		"auditd-log-file-path",
		"/app-audit/audit-pipe",
		"Path to the audit log file")
}

func RunNamedPipe(ctx context.Context, appCfg *appConfig, h *health.Health, optLoggerConfig *zap.Config) error {
	if optLoggerConfig == nil {
		cfg := zap.NewProductionConfig()
		optLoggerConfig = &cfg
	}

	var ll zapcore.Level = config.logLevel
	optLoggerConfig.Level = zap.NewAtomicLevelAt(ll)

	l, err := optLoggerConfig.Build()
	if err != nil {
		return err
	}

	defer func() {
		_ = l.Sync() //nolint
	}()

	logger = l.Sugar()

	auditd.SetLogger(logger)
	sshd.SetLogger(logger)

	distro, err := util.Distro()
	if err != nil {
		err := fmt.Errorf("failed to get os distro type: %w", err)
		logger.Errorf(err.Error())
		return err
	}

	mid, miderr := common.GetMachineID()
	if miderr != nil {
		return fmt.Errorf("failed to get machine id: %w", miderr)
	}

	nodeName, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		return fmt.Errorf("failed to get node name: %w", nodenameerr)
	}

	eg, groupCtx := errgroup.WithContext(ctx)

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(groupCtx, appEventsOutput, zapr.NewLogger(l))
	if auditfileerr != nil {
		return fmt.Errorf("failed to open audit log file: %w", auditfileerr)
	}

	eventWriter := auditevent.NewDefaultAuditEventWriter(auf)
	logins := make(chan common.RemoteUserLogin)
	pprov := metrics.NewPrometheusMetricsProvider()

	logger.Infoln("starting workers...")
	handleMetricsAndHealth(groupCtx, metricsCfg, eg, h)

	h.AddReadiness(namedpipe.NamedPipeProcessorComponentName)
	eg.Go(func() error {
		sshdProcessor := sshd.NewSshdProcessor(groupCtx, logins, nodeName, mid, eventWriter, pprov)
		npi := namedpipe.NewNamedPipeIngester(logger, h)
		if distro == util.DistroRocky {
			rp := rocky.NewRockyIngester(sshdLogFilePath, sshdProcessor, npi)
			err = rp.Ingest(groupCtx)
		} else {
			sli := syslog.NewSyslogIngester(sshdLogFilePath, sshdProcessor, npi)

			err = sli.Ingest(groupCtx)
		}

		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("syslog ingester exited (%v)", err)
		}
		return err
	})

	auditLogChanBufSize := 10000
	auditLogChan := make(chan string, auditLogChanBufSize)

	h.AddReadiness(namedpipe.NamedPipeProcessorComponentName)
	eg.Go(func() error {
		alp := auditlog.AuditLogIngester{
			FilePath:     auditdLogFilePath,
			AuditLogChan: auditLogChan,
		}

		err := alp.Ingest(groupCtx)
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("audit log ingester exited (%v)", err)
		}
		return err
	})

	h.AddReadiness(auditd.AuditdProcessorComponentName)
	eg.Go(func() error {
		ap := auditd.Auditd{
			Audits: auditLogChan,
			Logins: logins,
			EventW: eventWriter,
			Health: h,
		}

		err := ap.Read(groupCtx)
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
