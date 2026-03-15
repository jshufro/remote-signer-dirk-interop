package dirkdaemon

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/attestantio/dirk/testing/logger"
	"github.com/jshufro/remote-signer-dirk-interop/test/dirkdaemon/proc"
	"golang.org/x/sync/errgroup"
)

var portsMap = map[ID]uint32{
	ID1: 34925,
	ID2: 33015,
	ID3: 42923,
	ID4: 46453,
	ID5: 41283,
}

type ID int

const (
	ID_UNUSED ID = iota
	ID1
	ID2
	ID3
	ID4
	ID5
	ID_MAX
)

func StartDaemons(ctx context.Context, tmpdir string, ids ...ID) (map[uint64]string, map[int]*logger.LogCapture, error) {
	if len(ids) == 0 {
		ids = []ID{ID1, ID2, ID3, ID4, ID5}
	}
	ports := make(map[int]uint32)
	for _, id := range ids {
		ports[int(id)] = portsMap[id]
	}
	logCaptureMap := make(map[int]*logger.LogCapture)
	peerMap := make(map[uint64]string)
	for id, port := range ports {
		peerMap[uint64(id)] = fmt.Sprintf("signer-test%02d:%d", id, port)
	}
	wg := errgroup.Group{}
	logCaptureArr := make([]*logger.LogCapture, ID_MAX)
	for id, port := range ports {
		walletPath := filepath.Join(tmpdir, fmt.Sprintf("signer-test%02d", id))
		wg.Go(func() error {
			logCapture, err := newDirkDaemon(ctx, uint64(id), port, walletPath, peerMap)
			if err != nil {
				return fmt.Errorf("failed to create dirk daemon: %w", err)
			}
			logCaptureArr[id] = logCapture
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create dirk daemons: %w", err)
	}
	for i := range logCaptureArr {
		if logCaptureArr[i] != nil {
			logCaptureMap[i] = logCaptureArr[i]
		}
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
