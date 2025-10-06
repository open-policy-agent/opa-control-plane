package chain

import (
	"net/http"
	"slices"
)

type Chain []func(http.Handler) http.Handler

func New(hs ...func(http.Handler) http.Handler) Chain {
	return hs
}

func (c Chain) ThenFunc(h http.HandlerFunc) http.Handler {
	return c.then(h)
}

func (c Chain) then(h http.Handler) http.Handler {
	for _, mw := range slices.Backward(c) {
		h = mw(h)
	}
	return h
}
