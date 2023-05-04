package cmd

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
