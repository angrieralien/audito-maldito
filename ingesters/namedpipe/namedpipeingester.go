package namedpipe

import (
	"bufio"
	"context"
	"os"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"go.uber.org/zap"
)

type NamedPipeIngester struct {
}

func (n *NamedPipeIngester) Ingest(ctx context.Context, filePath string, logger *zap.SugaredLogger, h *common.Health) error {
	var file *os.File
	var err error
	ready := make(chan struct{})

	// os.OpenFile blocks. Put in go routine so we can gracefully exit.
	go func() {
		file, err = os.OpenFile(filePath, os.O_RDONLY, os.ModeNamedPipe)
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
	r := bufio.NewReader(file)
	fname := file.Name()
	logger.Infof("tailing %s", fname)

	go (func() {
		<-ctx.Done()
		file.Close()
	})()

	for {
		err := n.Process(ctx, r)
		if err != nil {
			return err
		}
	}
}

func (n *NamedPipeIngester) Process(ctx context.Context, r *bufio.Reader) error {
	return nil
}
