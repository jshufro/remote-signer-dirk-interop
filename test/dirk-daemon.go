package test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/attestantio/dirk/testing/daemon"
	"github.com/attestantio/dirk/testing/logger"
)

func getUnusedPort() (uint32, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("failed to get unused port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	return uint32(listener.Addr().(*net.TCPAddr).Port), nil
}

func StartDaemons(ctx context.Context, tmpdir string) (map[uint64]string, map[int]*logger.LogCapture, error) {
	portMap := make(map[int]uint32)
	logCaptureMap := make(map[int]*logger.LogCapture)
	for id := 1; id <= 5; id++ {
		port, err := getUnusedPort()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get unused port: %w", err)
		}
		portMap[id] = port
	}
	peerMap := make(map[uint64]string)
	for id, port := range portMap {
		peerMap[uint64(id)] = fmt.Sprintf("signer-test%02d:%d", id, port)
	}
	for id, port := range portMap {
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
	logCapture, _, err := daemon.New(
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
