package client

import (
	"github.com/go-resty/resty"
)

func NewR() *resty.Request {
	return resty.R()
}


