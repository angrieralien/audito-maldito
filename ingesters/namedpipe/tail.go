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
	logger.Infof("event %s tail", file.Name())

	for {
		select {
		case event, ok := <-watcher.Events:
			logger.Infof("event in tail %s", event)
			if !ok {
				break
			}
			if event.Has(fsnotify.Write) {
				logger.Infof("event in tail %s", event)
				err := callback(ctx, r)
				if err != nil {
					logger.Errorf(err.Error())
					return err

				}
			}
		}
	}
}
