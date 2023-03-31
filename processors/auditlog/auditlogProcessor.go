package auditlog

import (
	"bytes"
	"context"
	"io"
	"strings"
)

type AuditLogProcessor struct {
	AuditLogChan chan string
}

func (a *AuditLogProcessor) Process(ctx context.Context, r io.Reader, readBytes *bytes.Buffer, buf []byte) (int, error) {
	n, err := r.Read(buf[:cap(buf)])
	sp := strings.Split(string(buf[:n]), "\n")

	if len(sp) > 1 {
		a.AuditLogChan <- readBytes.String() + sp[0]
		for _, line := range sp[1 : len(sp)-1] {
			a.AuditLogChan <- line
		}
		readBytes.Truncate(0)
		readBytes.WriteString(sp[len(sp)-1])

	} else {
		readBytes.Write(buf[:n])
	}
	return n, err
}
