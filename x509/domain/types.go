package domain

import "math/big"



type pkcs1PublicKey struct {
	N *big.Int
	E int
}
