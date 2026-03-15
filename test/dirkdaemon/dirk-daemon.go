package dirkdaemon

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/attestantio/dirk/testing/logger"
	"github.com/jshufro/remote-signer-dirk-interop/test/dirkdaemon/proc"
)

var ports = map[int]uint32{
	1: 34925,
	2: 33015,
	3: 42923,
	4: 46453,
	5: 41283,
}

func StartDaemons(ctx context.Context, tmpdir string) (map[uint64]string, map[int]*logger.LogCapture, error) {
	logCaptureMap := make(map[int]*logger.LogCapture)
	peerMap := make(map[uint64]string)
	for id, port := range ports {
		peerMap[uint64(id)] = fmt.Sprintf("signer-test%02d:%d", id, port)
	}
	for id, port := range ports {
		walletPath := filepath.Join(tmpdir, fmt.Sprintf("signer-test%02d", id))
		logCapture, err := newDirkDaemon(ctx, uint64(id), port, walletPath, peerMap)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create dirk daemon: %w", err)
		}
		logCaptureMap[id] = logCapture
	}
	return peerMap, logCaptureMap, nil
}

func newDirkDaemon(ctx context.Context, id uint64, port uint32, tmpdir string, peerMap map[uint64]string) (*logger.LogCapture, error) {
	logCapture, _, err := proc.New(
		ctx,
		tmpdir,
		id,
		port,
		peerMap,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create dirk daemon: %w", err)
	}
	return logCapture, nil
}
