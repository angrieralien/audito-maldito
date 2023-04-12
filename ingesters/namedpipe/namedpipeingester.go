package namedpipe

import (
	"context"
	"os"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"go.uber.org/zap"
)

type NamedPipeIngester struct {
	FilePath string
}

func (a *NamedPipeIngester) Ingest(ctx context.Context, tailProcessor TailProcessor, logger *zap.SugaredLogger, h *common.Health) error {
	file, err := os.OpenFile(a.FilePath, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		logger.Fatal(err)
		return err
	}
	h.OnReady()
	return Tail(ctx, file, logger, tailProcessor)
}
