//go:build cuda

package main

// #include <stdlib.h>
import "C"

import (
	"fmt"

	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

//export PrepareCudaProver
func PrepareCudaProver(dataDir *C.char, plonk C.int) (err *C.char) {
	defer func() {
		if r := recover(); r != nil {
			err = C.CString(fmt.Sprint(r))
		}
	}()
	dir := C.GoString(dataDir)
	if plonk != 0 {
		sp1.PreparePlonk(dir)
	} else {
		sp1.PrepareGroth16(dir)
	}
	return nil
}
