package main

import "github.com/gourdian25/gourdiangin"

func main() {
	// To stop the server from another process:
	err := gourdiangin.StopProcessFromPIDFile("tmp/myapp.pid", nil)
	if err != nil {
		panic(err)
	}
}
