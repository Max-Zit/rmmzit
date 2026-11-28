package web

import (
	"context"

	"github.com/max-zit/rmmzit/internal/store"
)

// RemotePolicy is the remote desktop part of a policy (issue #20).
type RemotePolicy struct {
	// Consent: the signed-in user must allow each remote desktop session
	// (also view only). Without a user to ask (sign-in or locked screen)
	// the session starts; the technician then sees only that screen.
	Consent bool `json:"consent"`
}

// consentAgentVersion is the first agent that can ask its user.
const consentAgentVersion = "0.17.0"

func (pr *policyResolver) remote(deviceID int64) (*RemotePolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.Remote != nil }); l != nil {
		return l.Settings.Remote, l
	}
	return nil, nil
}

// Messages of the helper about the user's answer (written in English by the
// agent, translated for the technician; see internal/agent/rdstart.go).
const (
	msgConsentRefused = "The user refused the remote desktop session."
	msgConsentTimeout = "The user did not answer within a minute; the remote desktop session was not started."
)

// rdConsent says whether the user of the device must allow a session, and
// refuses one when the agent is too old to ask.
func (s *Server) rdConsent(ctx context.Context, d *store.Device) (bool, error) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return false, err
	}
	rp, _ := pr.remote(d.ID)
	if rp == nil || !rp.Consent {
		return false, nil
	}
	if tooOldFor(d, consentAgentVersion) {
		return true, uiErr("This device's policy asks the user to allow remote desktop sessions; its agent must be 0.17.0 or newer. Update the agent first.")
	}
	return true, nil
}
