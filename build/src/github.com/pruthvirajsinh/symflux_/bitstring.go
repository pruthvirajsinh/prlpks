/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// Package symflux provides set reconciliation core functionality
// and the supporting math: polynomial arithmetic over finite fields,
// factoring and rational function interpolation.
package symflux

import (
	"bytes"
	"fmt"
	"math/big"
)

type Bitstring struct {
	buf  []byte
	bits int
}

func NewBitstring(bits int) *Bitstring {
	n := bits / 8
	if bits%8 != 0 {
		n++
	}
	return &Bitstring{buf: make([]byte, n), bits: bits}
}

func NewZpBitstring(zp *Zp) *Bitstring {
	bs := NewBitstring(zp.P.BitLen())
	bs.SetBytes(zp.Bytes())
	return bs
}

func (bs *Bitstring) BitLen() int {
	return bs.bits
}

func (bs *Bitstring) ByteLen() int {
	return len(bs.buf)
}

func (bs *Bitstring) bitIndex(bit int) (int, uint) {
	return bit / 8, uint(bit % 8)
}

func (bs *Bitstring) Get(bit int) int {
	bytePos, bitPos := bs.bitIndex(bit)
	if (bs.buf[bytePos] & (byte(1) << (8 - bitPos - 1))) != 0 {
		return 1
	}
	return 0
}

func (bs *Bitstring) Set(bit int) {
	bytePos, bitPos := bs.bitIndex(bit)
	bs.buf[bytePos] |= (byte(1) << (8 - bitPos - 1))
}

func (bs *Bitstring) Unset(bit int) {
	bytePos, bitPos := bs.bitIndex(bit)
	bs.buf[bytePos] &^= (byte(1) << (8 - bitPos - 1))
}

func (bs *Bitstring) Flip(bit int) {
	bytePos, bitPos := bs.bitIndex(bit)
	bs.buf[bytePos] ^= (byte(1) << (8 - bitPos - 1))
}

func (bs *Bitstring) SetBytes(buf []byte) {
	for i := 0; i < len(bs.buf); i++ {
		if i < len(buf) {
			bs.buf[i] = buf[i]
		} else {
			bs.buf[i] = byte(0)
		}
	}
	bytePos, bitPos := bs.bitIndex(bs.bits)
	if bitPos != 0 {
		mask := ^((byte(1) << (8 - bitPos)) - 1)
		bs.buf[bytePos] &= mask
	}
}

func (bs *Bitstring) Lsh(n uint) {
	i := big.NewInt(int64(0)).SetBytes(bs.buf)
	i.Lsh(i, n)
	bs.SetBytes(i.Bytes())
}

func (bs *Bitstring) Rsh(n uint) {
	i := big.NewInt(int64(0)).SetBytes(bs.buf)
	i.Rsh(i, n)
	bs.SetBytes(i.Bytes())
}

func (bs *Bitstring) String() string {
	if bs == nil {
		return "nil"
	}
	w := bytes.NewBuffer(nil)
	for i := 0; i < bs.bits; i++ {
		fmt.Fprintf(w, "%d", bs.Get(i))
	}
	return w.String()
}

func (bs *Bitstring) Bytes() []byte {
	w := bytes.NewBuffer(nil)
	w.Write(bs.buf)
	return w.Bytes()
}

func ReverseBytes(buf []byte) (result []byte) {
	l := len(buf)
	result = make([]byte, l)
	for i := 0; i < l; i++ {
		result[i] = ReverseByte(buf[i])
	}
	return
}

func ReverseByte(b byte) (r byte) {
	for i := uint(0); i < 8; i++ {
		r |= ((b >> (7 - i)) & 1) << i
	}
	return
}
