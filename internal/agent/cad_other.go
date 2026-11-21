//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/max-zit/rmmzit/internal/proto"
)

func init() {
	register(proto.KindRDCAD, func(context.Context, json.RawMessage) (any, error) {
		return nil, errors.New("Ctrl+Alt+Del is a Windows key combination")
	})
}
