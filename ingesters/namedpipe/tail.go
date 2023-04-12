package namedpipe

import (
	"bufio"
	"context"
	"os"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type TailProcessor func(context.Context, *bufio.Reader) error

func Tail(ctx context.Context, file *os.File, logger *zap.SugaredLogger, callback TailProcessor) error {
	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	defer watcher.Close()
	err = watcher.Add(file.Name())
	if err != nil {
		logger.Error(err)
		return err
	}
	r := bufio.NewReader(file)
	fname := file.Name()
	logger.Infof("tailing %s", fname)

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
