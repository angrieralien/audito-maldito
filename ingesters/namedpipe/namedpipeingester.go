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
	var file *os.File
	var err error
	ready := make(chan struct{})

	// os.OpenFile blocks. Put in go routine so we can gracefully exit.
	go func() {
		file, err = os.OpenFile(a.FilePath, os.O_RDONLY, os.ModeNamedPipe)
		close(ready)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ready:
	}

	if err != nil {
		return err
	}

	h.OnReady()
	return Tail(ctx, file, logger, tailProcessor)
}
