package accountcache

import (
	"sync"

	e2wt "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type AccountCache struct {
	sync.Map
}

func (c *AccountCache) Get(key [48]byte) e2wt.Account {
	account, ok := c.Load(key)
	if !ok {
		return nil
	}
	return account.(e2wt.Account)
}

func (c *AccountCache) Set(key [48]byte, account e2wt.Account) {
	c.Store(key, account)
}
