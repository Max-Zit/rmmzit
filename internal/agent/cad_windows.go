package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/rd"
)

// Ctrl+Alt+Del for remote desktop. Windows accepts SendSAS only from a
// service (this one, in session 0) and only when the policy
// SoftwareSASGeneration allows services (1) or services and ease of access
// programs (3). When it does not, the policy is allowed for this one call
// and put back right after, so the computer's setting stays as it was.

const sasPolicyKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

var cadMu sync.Mutex

func init() {
	register(proto.KindRDCAD, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return nil, sendSAS()
	})
}

func sendSAS() error {
	cadMu.Lock()
	defer cadMu.Unlock()
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, sasPolicyKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return errors.New("Ctrl+Alt+Del: the policy cannot be read: " + err.Error())
	}
	defer k.Close()
	old, _, gerr := k.GetIntegerValue("SoftwareSASGeneration")
	if gerr != nil || (old != 1 && old != 3) {
		if err := k.SetDWordValue("SoftwareSASGeneration", 1); err != nil {
			return errors.New("Ctrl+Alt+Del: the policy cannot be set: " + err.Error())
		}
		defer func() {
			// Winlogon reads the policy while it handles the call: wait a
			// moment before the computer's own setting comes back.
			time.Sleep(time.Second)
			if gerr != nil {
				_ = k.DeleteValue("SoftwareSASGeneration")
			} else {
				_ = k.SetDWordValue("SoftwareSASGeneration", uint32(old)) // #nosec G115 -- a DWORD value read from the registry
			}
		}()
	}
	return rd.CtrlAltDel()
}
