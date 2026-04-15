package fork

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/typeconv"
)

type Fork struct {
	CurrentVersion  []byte
	PreviousVersion []byte
	Epoch           uint64
}

type ForkInfo struct {
	Fork                  Fork
	GenesisValidatorsRoot []byte
}

type jsonForkInfo struct {
	Fork                  *api.Fork `json:"fork"`
	GenesisValidatorsRoot string    `json:"genesis_validators_root"`
}

func (f *ForkInfo) UnmarshalJSON(data []byte) error {
	var jsonForkInfo jsonForkInfo
	var err error
	if err = json.Unmarshal(data, &jsonForkInfo); err != nil {
		return err
	}
	currentVersion, err := typeconv.DecodeHex(jsonForkInfo.Fork.CurrentVersion)
	if err != nil {
		return fmt.Errorf("failed to decode current_version: %w", err)
	}
	previousVersion, err := typeconv.DecodeHex(jsonForkInfo.Fork.PreviousVersion)
	if err != nil {
		return fmt.Errorf("failed to decode previous_version: %w", err)
	}
	e, err := strconv.ParseUint(jsonForkInfo.Fork.Epoch, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse fork epoch: %w", err)
	}

	if len(currentVersion) != 4 {
		return errors.New("current_version is not 4 bytes")
	}
	if len(previousVersion) != 4 {
		return errors.New("previous_version is not 4 bytes")
	}

	f.Fork = Fork{
		CurrentVersion:  currentVersion,
		PreviousVersion: previousVersion,
		Epoch:           e,
	}
	f.GenesisValidatorsRoot, err = typeconv.DecodeHex(jsonForkInfo.GenesisValidatorsRoot)
	if err != nil {
		return fmt.Errorf("failed to decode genesis_validators_root: %w", err)
	}
	if len(f.GenesisValidatorsRoot) != 32 {
		return errors.New("genesis_validators_root is not 32 bytes")
	}
	return nil
}

func (f *ForkInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonForkInfo{
		Fork: &api.Fork{
			CurrentVersion:  typeconv.EncodeHex(f.Fork.CurrentVersion),
			PreviousVersion: typeconv.EncodeHex(f.Fork.PreviousVersion),
			Epoch:           fmt.Sprint(f.Fork.Epoch),
		},
		GenesisValidatorsRoot: typeconv.EncodeHex(f.GenesisValidatorsRoot),
	})
}

func (f *ForkInfo) ForkVersion(epoch uint64) []byte {
	if epoch < f.Fork.Epoch {
		return f.Fork.PreviousVersion
	}
	return f.Fork.CurrentVersion
}

type forkInfoWithDomainType struct {
	forkInfo   *ForkInfo
	domainType domains.DomainType
}

func (f *ForkInfo) WithDomainType(domainType domains.DomainType) *forkInfoWithDomainType {
	return &forkInfoWithDomainType{
		forkInfo:   f,
		domainType: domainType,
	}
}

func (f *forkInfoWithDomainType) Domain(epoch uint64) domains.Domain {
	return domains.ComputeDomain(
		f.domainType,
		domains.ForkVersion(f.forkInfo.ForkVersion(epoch)),
		domains.Root(f.forkInfo.GenesisValidatorsRoot),
	)
}
