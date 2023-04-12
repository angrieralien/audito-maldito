package namedpipe

import (
	"bufio"
	"context"
	"os"

	"go.uber.org/zap"
)

type TailProcessor func(context.Context, *bufio.Reader) error

func Tail(ctx context.Context, file *os.File, logger *zap.SugaredLogger, callback TailProcessor) error {
	r := bufio.NewReader(file)
	fname := file.Name()
	logger.Infof("tailing %s", fname)

	go (func() {
		<-ctx.Done()
		logger.Infof("before close %s", fname)
		file.Close()
		logger.Infof("before close %s", fname)
	})()

	for {
		logger.Infof("before callback %s", fname)
		err := callback(ctx, r)
		logger.Infof("after callack %s", fname)
		if err != nil {
			logger.Errorf("tailing threw error: %s", err)
			return err
		}
	}
}
