/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// primegen is a utility for generating large primes that bound
// a given bit length.
package main

import (
	"crypto/rand"
	"fmt"
)

func main() {
	for _, n := range []int{128, 160, 256, 512} {
		p, err := rand.Prime(rand.Reader, n+1)
		if err != nil {
			panic(err)
		}
		fmt.Printf("var p_%v = big.NewInt(0).SetBytes([]byte{", n)
		data := p.Bytes()
		for i, b := range data {
			if i > 0 {
				fmt.Printf(",")
			}
			if i < len(data)-1 && i%8 == 0 {
				fmt.Printf("\n\t")
			}
			fmt.Printf("0x%x", b)
		}
		fmt.Printf("})\n\n")
	}
}
