package tuf

import (
	"errors"

	"github.com/WatchBeam/clock"
)

func withClock(mc clock.Clock) Option {
	return func(c *Client) {
		c.clock = mc
	}
}

func loadOnStart(load bool) Option {
	return func(c *Client) {
		c.loadOnStart = load
	}
}

func (c *Client) getFIMMap() (FimMap, error) {
	type res struct {
		fims FimMap
		err  error
	}
	resultC := make(chan res)
	c.jobs <- func(rm *repoMan) {
		if rm.targets == nil {
			resultC <- res{nil, errors.New("no targets")}
			return
		}
		resultC <- res{rm.targets.paths.clone(), nil}
	}
	result := <-resultC
	return result.fims, result.err
}
