package main

/*
#include "./lib/babybear.h"
*/
import "C"

func main() {
}

//export Test
func Test(ptr *C.char) {
	str := C.GoString(ptr)
	println(str)
}

//export Test2
func Test2() {
	println("test2")
}

//export Test3
func Test3(a uint32) uint32 {
	cuint := C.uint32_t(a)
	result := C.babybearextinv(cuint, cuint, cuint, cuint, cuint)
	return uint32(result)
}
