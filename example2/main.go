package main

import (
	"log"

	"github.com/gourdian25/gourdiangin"
)

func main() {
	// To stop the server from another process:
	err := gourdiangin.StopProcessFromPIDFile("tmp/myapp.pid", nil)
	if err != nil {
		log.Printf("Failed to stop process: %v", err)
	} else {
		log.Println("Process stopped successfully")
	}
}
