package cmd

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"
)

var (
	config  *appConfig
	rootCmd = &cobra.Command{
		Use:   "audito-maldito",
		Short: "Hugo is a very fast static site generator",
		Long: `audito-maldito is a daemon that monitors OpenSSH server logins and
	produces structured audit events describing what authenticated users
	did while logged in (e.g., what programs they executed).`,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	config = &appConfig{}
	var logLevel *int

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	rootCmd.PersistentFlags().StringVar(
		&config.bootID,
		"boot-id",
		"",
		"Optional Linux boot ID to use when reading from the journal")
	rootCmd.PersistentFlags().StringVar(
		&config.auditlogpath,
		"audit-log-path",
		"/app-audit/audit.log",
		"Path to the audit log file")
	rootCmd.PersistentFlags().StringVar(
		&config.auditLogDirPath,
		"audit-dir-path",
		"/var/log/audit",
		"Path to the Linux audit log directory")
	rootCmd.PersistentFlags().BoolVar(
		&config.metricsConfig.enableMetrics,
		"metrics",
		false,
		"Enable Prometheus HTTP /metrics server")
	rootCmd.PersistentFlags().BoolVar(
		&config.metricsConfig.enableHealthz,
		"healthz",
		false,
		"Enable HTTP health endpoints server")
	rootCmd.PersistentFlags().BoolVar(
		&config.metricsConfig.enableAuditMetrics,
		"audit-metrics",
		false,
		"Enable Prometheus audit metrics")
	rootCmd.PersistentFlags().DurationVar(
		&config.metricsConfig.httpServerReadTimeout,
		"http-server-read-timeout",
		DefaultHTTPServerReadTimeout,
		"HTTP server read timeout")
	rootCmd.PersistentFlags().DurationVar(
		&config.metricsConfig.httpServerReadHeaderTimeout,
		"http-server-read-header-timeout",
		DefaultHTTPServerReadHeaderTimeout,
		"HTTP server read header timeout")
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
	rootCmd.PersistentFlags().IntVar(
		logLevel,
		"log-level",
		0,
		`Set the log level according to zapcore.Level:
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
	var ll zapcore.Level = zapcore.Level(*logLevel)
	config.logLevel = ll
	rootCmd.AddCommand(journaldCmd)
	rootCmd.AddCommand(namedpipeCmd)
}
