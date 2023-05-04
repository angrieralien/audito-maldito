package cmd

import (
	"context"
	"flag"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/ingesters/journald"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
	"github.com/metal-toolbox/audito-maldito/internal/util"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
	"github.com/metal-toolbox/audito-maldito/processors/varlogsecure"
)

var rootCmd = &cobra.Command{
	Use:   "audito-maldito",
	Short: "Hugo is a very fast static site generator",
	Long: `audito-maldito is a daemon that monitors OpenSSH server logins and
	produces structured audit events describing what authenticated users
	did while logged in (e.g., what programs they executed).`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	config := &appConfig{}
	var logLevel *int

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	rootCmd.PersistentFlags().StringVar(&config.bootID, "boot-id", "", "Optional Linux boot ID to use when reading from the journal")
	rootCmd.PersistentFlags().StringVar(&config.auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")
	rootCmd.PersistentFlags().StringVar(&config.auditLogDirPath, "audit-dir-path", "/var/log/audit",
		"Path to the Linux audit log directory")

	rootCmd.PersistentFlags().BoolVar(&config.metricsConfig.enableMetrics, "metrics", false, "Enable Prometheus HTTP /metrics server")
	rootCmd.PersistentFlags().BoolVar(&config.metricsConfig.enableHealthz, "healthz", false, "Enable HTTP health endpoints server")
	rootCmd.PersistentFlags().BoolVar(&config.metricsConfig.enableAuditMetrics, "audit-metrics", false, "Enable Prometheus audit metrics")
	rootCmd.PersistentFlags().DurationVar(&config.metricsConfig.httpServerReadTimeout, "http-server-read-timeout",
		DefaultHTTPServerReadTimeout, "HTTP server read timeout")
	rootCmd.PersistentFlags().DurationVar(&config.metricsConfig.httpServerReadHeaderTimeout, "http-server-read-header-timeout",
		DefaultHTTPServerReadHeaderTimeout, "HTTP server read header timeout")
	rootCmd.PersistentFlags().DurationVar(
		&config.metricsConfig.auditMetricsSecondsInterval,
		"audit-seconds-interval",
		DefaultAuditCheckInterval,
		"Interval in seconds to collect audit metrics")
	rootCmd.PersistentFlags().IntVar(
		&config.metricsConfig.auditLogWriteTimeSecondThreshold,
		"audit-log-last-modify-seconds-threshold",
		DefaultAuditModifyTimeThreshold,
		"seconds since last write to audit.log before alerting")

	rootCmd.PersistentFlags().IntVar(logLevel, "log-level", 0, `Set the log level according to zapcore.Level:
	// DebugLevel logs are typically voluminous, and are usually disabled in
	// production.
	DebugLevel = -1
	// InfoLevel is the default logging priority.
	InfoLevel = 0
	// WarnLevel logs are more important than Info, but don't need individual
	// human review.
	WarnLevel = 1
	// ErrorLevel logs are high-priority. If an application is running smoothly,
	// it shouldn't generate any error-level logs.
	ErrorLevel = 2
	// DPanicLevel logs are particularly important errors. In development the
	// logger panics after writing the message.
	DPanicLevel = 3
	// PanicLevel logs a message, then panics.
	PanicLevel = 4
	// FatalLevel logs a message, then calls os.Exit(1).
	FatalLevel = 5
`)

	config.logLevel = config.logLevel
	rootCmd.AddCommand(journaldCmd)
	rootCmd.AddCommand(namedpipeCmd)
}

var logger *zap.SugaredLogger

const (
	// DefaultHTTPServerReadTimeout is the default HTTP server read timeout.
	DefaultHTTPServerReadTimeout = 1 * time.Second
	// DefaultHTTPServerReadHeaderTimeout is the default HTTP server read header timeout.
	DefaultHTTPServerReadHeaderTimeout = 5 * time.Second
	// DefaultAuditCheckInterval when to check audit.log modify time.
	DefaultAuditCheckInterval = 15 * time.Second
	// DefaultAuditModifyTimeThreshold seconds since last write to audit.log before alerting.
	DefaultAuditModifyTimeThreshold = 86400
)

type metricsConfig struct {
	enableMetrics                    bool
	enableHealthz                    bool
	enableAuditMetrics               bool
	httpServerReadTimeout            time.Duration
	httpServerReadHeaderTimeout      time.Duration
	auditMetricsSecondsInterval      time.Duration
	auditLogWriteTimeSecondThreshold int
}

type appConfig struct {
	bootID          string
	auditlogpath    string
	auditLogDirPath string
	metricsConfig   metricsConfig
	logLevel        zapcore.Level
}

func parseFlags(osArgs []string) (*appConfig, error) {
	flagSet := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	config := &appConfig{
		logLevel: zapcore.InfoLevel,
	}

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flagSet.StringVar(&config.bootID, "boot-id", "", "Optional Linux boot ID to use when reading from the journal")
	flagSet.StringVar(&config.auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")
	flagSet.StringVar(&config.auditLogDirPath, "audit-dir-path", "/var/log/audit",
		"Path to the Linux audit log directory")
	flagSet.Var(&config.logLevel, "log-level", "Set the log level according to zapcore.Level")
	flagSet.BoolVar(&config.metricsConfig.enableMetrics, "metrics", false, "Enable Prometheus HTTP /metrics server")
	flagSet.BoolVar(&config.metricsConfig.enableHealthz, "healthz", false, "Enable HTTP health endpoints server")
	flagSet.BoolVar(&config.metricsConfig.enableAuditMetrics, "audit-metrics", false, "Enable Prometheus audit metrics")
	flagSet.DurationVar(&config.metricsConfig.httpServerReadTimeout, "http-server-read-timeout",
		DefaultHTTPServerReadTimeout, "HTTP server read timeout")
	flagSet.DurationVar(&config.metricsConfig.httpServerReadHeaderTimeout, "http-server-read-header-timeout",
		DefaultHTTPServerReadHeaderTimeout, "HTTP server read header timeout")
	flagSet.DurationVar(
		&config.metricsConfig.auditMetricsSecondsInterval,
		"audit-seconds-interval",
		DefaultAuditCheckInterval,
		"Interval in seconds to collect audit metrics")
	flagSet.IntVar(
		&config.metricsConfig.auditLogWriteTimeSecondThreshold,
		"audit-log-last-modify-seconds-threshold",
		DefaultAuditModifyTimeThreshold,
		"seconds since last write to audit.log before alerting")

	if err := flagSet.Parse(osArgs[1:]); err != nil {
		return nil, err
	}

	return config, nil
}

func runProcessorsForSSHLogins(
	ctx context.Context,
	logins chan<- common.RemoteUserLogin,
	eg *errgroup.Group,
	distro util.DistroType,
	mid string,
	nodename string,
	bootID string,
	lastReadJournalTS uint64,
	eventWriter *auditevent.EventWriter,
	h *health.Health,
	pprov *metrics.PrometheusMetricsProvider,
) {
	sshdProcessor := sshd.NewSshdProcessor(ctx, logins, nodename, mid, eventWriter, pprov)

	//nolint:exhaustive // In this case it's actually simpler to just default to journald
	switch distro {
	case util.DistroRocky:
		h.AddReadiness(varlogsecure.VarLogSecureComponentName)

		// TODO: handle last read timestamp
		eg.Go(func() error {
			vls := varlogsecure.VarLogSecure{
				L:             logger,
				Logins:        logins,
				NodeName:      nodename,
				MachineID:     mid,
				AuWriter:      eventWriter,
				Health:        h,
				Metrics:       pprov,
				SshdProcessor: sshdProcessor,
			}

			err := vls.Read(ctx)
			logger.Infof("varlogsecure worker exited (%v)", err)
			return err
		})
	default:
		h.AddReadiness(journald.JournaldReaderComponentName)

		eg.Go(func() error {
			jp := journald.Processor{
				BootID:        bootID,
				MachineID:     mid,
				NodeName:      nodename,
				Distro:        distro,
				EventW:        eventWriter,
				Logins:        logins,
				CurrentTS:     lastReadJournalTS,
				Health:        h,
				Metrics:       pprov,
				SshdProcessor: sshdProcessor,
			}

			err := jp.Read(ctx)
			logger.Infof("journald worker exited (%v)", err)
			return err
		})
	}
}

// handleMetricsAndHealth starts a HTTP server on port 2112 to serve metrics
// and health endpoints.
//
// If metrics are disabled, the /metrics endpoint will return 404.
// If health is disabled, the /readyz endpoint will return 404.
// If both are disabled, the HTTP server will not be started.
func handleMetricsAndHealth(ctx context.Context, mc metricsConfig, eg *errgroup.Group, h *health.Health) {
	server := &http.Server{
		Addr:              ":2112",
		ReadTimeout:       mc.httpServerReadTimeout,
		ReadHeaderTimeout: mc.httpServerReadHeaderTimeout,
	}

	if mc.enableMetrics {
		http.Handle("/metrics", promhttp.Handler())
	}

	if mc.enableHealthz {
		http.Handle("/readyz", h.ReadyzHandler())
		// TODO: Add livez endpoint
	}

	if mc.enableMetrics || mc.enableHealthz {
		eg.Go(func() error {
			logger.Infof("starting HTTP server on address '%s'...", server.Addr)
			if err := server.ListenAndServe(); err != nil {
				return err
			}
			return nil
		})

		eg.Go(func() error {
			<-ctx.Done()
			logger.Infoln("stopping HTTP server...")
			return server.Shutdown(ctx)
		})
	}
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

func handleAuditLogMetrics(
	ctx context.Context,
	eg *errgroup.Group,
	pprov *metrics.PrometheusMetricsProvider,
	auditMetricsSecondsInterval time.Duration,
	auditLogWriteTimeSecondThreshold int,
	enableAuditMetrics bool,
) {
	if !enableAuditMetrics {
		return
	}

	auditLogFilePath := "/var/log/audit/audit.log"

	eg.Go(func() error {
		ticker := time.NewTicker(auditMetricsSecondsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s, err := os.Stat(auditLogFilePath)
				if err != nil {
					logger.Errorf("error stat-ing %s", auditLogFilePath)
					continue
				}

				if time.Since(s.ModTime()).Seconds() > float64(auditLogWriteTimeSecondThreshold) {
					pprov.SetAuditLogCheck(0, strconv.Itoa(auditLogWriteTimeSecondThreshold))
				} else {
					pprov.SetAuditLogCheck(1, strconv.Itoa(auditLogWriteTimeSecondThreshold))
				}

				pprov.SetAuditLogModifyTime(float64(s.ModTime().Unix()))
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
}
