package rd

import "golang.org/x/sys/windows"

// While a technician is connected the screen stays on: with the monitor
// asleep the picture does not change (the remote desktop showed the time
// the monitor went off), and some computers stop the screen capture until
// it wakes up.

var pSetThreadExecutionState = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadExecutionState")

const (
	esSystemRequired  = 0x00000001
	esDisplayRequired = 0x00000002
	esContinuous      = 0x80000000
)

// keepAwake keeps the display and the computer on until release is
// called; it must stay on the calling thread (the state belongs to it).
func keepAwake() (release func()) {
	_, _, _ = pSetThreadExecutionState.Call(esContinuous | esDisplayRequired | esSystemRequired)
	return func() { _, _, _ = pSetThreadExecutionState.Call(esContinuous) }
}

// wakeDisplay turns a sleeping monitor on: a pointer move of one pixel
// there and back (no click, nothing typed).
func wakeDisplay() {
	_ = send([]input{mouse(mouseInput{dx: 1, flags: mouseMove}), mouse(mouseInput{dx: -1, flags: mouseMove})})
}
