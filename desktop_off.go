//go:build !desktop

package main

import "os"

const desktopAvailable = false

func runDesktop(string, <-chan os.Signal) {}
