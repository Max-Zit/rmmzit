package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/rd"
)

// The service cannot see the desktop (it runs in session 0), so rd.start
// launches a helper process — this same program with the rdhelper command —
// in the console session. The helper connects its own stream to the server.

// Linux desktops the remote desktop cannot use.
var (
	errWayland = errors.New("remote desktop is not possible: the desktop of this computer runs on Wayland, which does not let a background service see the screen or control it. Sign in with an X11 (Xorg) session, or use the Terminal")
	errNoX     = errors.New("no graphical desktop is running on this computer: use the Terminal")
)

// helperDir is the data directory passed to helpers (set by Run).
var helperDir string

func init() {
	register(proto.KindRDStart, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.RDStart
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		if a.Session == "" || a.Token == "" || len(a.Session) > 64 || len(a.Technician) > 120 {
			return nil, errors.New("bad remote desktop request")
		}
		if err := startHelper(helperDir, a); err != nil {
			if errors.Is(err, errWayland) || errors.Is(err, errNoX) {
				return nil, err // the console translates these
			}
			return nil, fmt.Errorf("cannot start the remote desktop helper: %w", err)
		}
		return nil, nil
	})
}

// HelperOptions are the settings of a remote desktop helper.
type HelperOptions struct {
	Notice, Clipboard, ViewOnly bool
	// Consent: ask the signed-in user to allow the session first.
	Consent bool
}

// ConsentTimeout is how long the user has to answer.
const ConsentTimeout = 60 * time.Second

// Messages to the technician about the user's answer (the console
// translates them).
const (
	msgConsentWait    = "Waiting for the user to allow the remote desktop session."
	msgConsentRefused = "The user refused the remote desktop session."
	msgConsentTimeout = "The user did not answer within a minute; the remote desktop session was not started."
	msgConsentNoAsk   = "This computer cannot ask its user, and its policy requires the user's consent."
)

// RunHelper is the rdhelper command: it connects the stream (the token came
// on stdin), asks the user first when the policy wants it, and serves the
// desktop.
func RunHelper(ctx context.Context, dir, session, technician, token string, o HelperOptions, log *slog.Logger) error {
	ws, err := dialStream(ctx, dir, session, token)
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	if o.Consent {
		say := func(t, text string) {
			b, _ := json.Marshal(map[string]string{"t": t, "text": text})
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = ws.Write(wctx, websocket.MessageText, b)
			cancel()
		}
		say("wait", msgConsentWait)
		answer := rd.AskConsent(ctx, technician, o.ViewOnly, ConsentTimeout)
		log.Info("remote desktop consent", "session", session, "answer", answer)
		switch answer {
		case rd.ConsentYes, rd.ConsentNobody:
		case rd.ConsentNo:
			say("error", msgConsentRefused)
			return ws.Close(websocket.StatusNormalClosure, "refused")
		case rd.ConsentTimeout:
			say("error", msgConsentTimeout)
			return ws.Close(websocket.StatusNormalClosure, "no answer")
		default:
			say("error", msgConsentNoAsk)
			return ws.Close(websocket.StatusNormalClosure, "cannot ask")
		}
	}
	log.Info("remote desktop session started", "session", session, "technician", technician, "view_only", o.ViewOnly)
	err = rd.Serve(ctx, ws, technician, o.Notice, o.Clipboard, o.ViewOnly, log)
	log.Info("remote desktop session ended", "session", session, "err", err)
	return err
}

// dialStream connects a session stream to the server with this device's
// TLS identity and the session token.
func dialStream(ctx context.Context, dir, session, token string) (*websocket.Conn, error) {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, err
	}
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	cert, err := clientCert(key)
	if err != nil {
		return nil, err
	}
	hc := httpClient(pinnedTLS(cfg.Fingerprint, cert))
	hc.Timeout = 0
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(dctx, cfg.ServerURL+proto.PathStream+"?session="+url.QueryEscape(session), &websocket.DialOptions{
		HTTPClient: hc,
		HTTPHeader: http.Header{"User-Agent": {"rmmzit-agent/" + Version}, "X-Cz-Session-Token": {strings.TrimSpace(token)}},
	})
	if err != nil {
		return nil, fmt.Errorf("stream: %w", err)
	}
	ws.SetReadLimit(1 << 20)
	return ws, nil
}
