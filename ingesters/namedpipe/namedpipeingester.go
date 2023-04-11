package namedpipe

import (
	"context"
	"os"

	"go.uber.org/zap"
)

type NamedPipeIngester struct {
	FilePath string
}

func (a *NamedPipeIngester) Ingest(ctx context.Context, tailProcessor TailProcessor, logger *zap.SugaredLogger) error {
	file, err := os.OpenFile(a.FilePath, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		logger.Fatal(err)
		return err
	}
	return Tail(ctx, file, logger, tailProcessor)
}
