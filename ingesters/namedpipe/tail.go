package namedpipe

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type TailProcessor func(context.Context, io.Reader, *bytes.Buffer, []byte) (int, error)

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
	currentLog := bytes.NewBufferString("")
	buf := make([]byte, 0, 4*1024)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				break
			}
			if event.Has(fsnotify.Write) {
				for {
					n, err := callback(ctx, r, currentLog, buf)
					if err != nil {
						logger.Errorln(err)
					}
					if n == 0 {
						if err == nil {
							break
						}
						if err == io.EOF {
							break
						}
						logger.Error(err.Error())
						return err
					}
				}
			}
		}
	}
}
