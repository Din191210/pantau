//go:build desktop

package main

import (
	"os"

	webview "github.com/webview/webview_go"
)

const desktopAvailable = true

// runDesktop blocks on the main thread (GTK/Cocoa requirement) until the window
// closes or quit fires.
func runDesktop(url string, quit <-chan os.Signal) {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Pantau")
	w.SetSize(1280, 800, webview.HintNone)
	w.Navigate(url)
	go func() {
		<-quit
		w.Dispatch(w.Terminate)
	}()
	w.Run()
}
