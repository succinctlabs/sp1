package main

/*
#cgo LDFLAGS: ./lib/libbabybear.a -ldl
#include "./lib/babybear.h"
*/
import "C"

import (
	root "github.com/succinctlabs/sp1-recursion-gnark/cmd"
)

func main() {
	root.Execute()
}
