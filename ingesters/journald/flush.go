package journald

import (
	"fmt"
	"os"
	"time"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

var defaultSleep = 1 * time.Second

const (
	onlyUserReadable = 0o600
)

// writes the last read timestamp to a file
// Note we don't fail if we can't write the file nor read the directory
// as we intend to go through the defer statements and exit.
// If this fails, we will just start reading from the beginning of the journal.
func flushLastRead(lastReadTimestamp uint64) {
	logger.Infof("flushing last read timestamp %d", lastReadTimestamp)

	if err := common.EnsureFlushDirectory(); err != nil {
		logger.Errorf("failed to ensure flush directory: %v", err)
		return
	}

	// The WriteFile function ensures the file will only contain
	// *exactly* what we write to it by either creating a new file,
	// or by truncating an existing file.
	err := os.WriteFile(common.TimeFlushPath, []byte(fmt.Sprintf("%d", lastReadTimestamp)), onlyUserReadable)
	if err != nil {
		logger.Errorf("failed to write flush file: %s", err)
	}
}
