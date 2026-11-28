package rd

// Consent is the answer of the person at the computer to a remote desktop
// request (a policy can require it).
type Consent int

const (
	// ConsentYes: the user allowed the session.
	ConsentYes Consent = iota
	// ConsentNo: the user refused it.
	ConsentNo
	// ConsentTimeout: the user did not answer in time.
	ConsentTimeout
	// ConsentNobody: nobody can answer (nobody signed in, or the screen is
	// locked); the technician sees only the sign-in screen.
	ConsentNobody
	// ConsentUnavailable: this computer cannot ask its user.
	ConsentUnavailable
)

// consentText is the question shown to the user (ASCII on Linux).
func consentText(technician string, viewOnly bool) string {
	what := "connect to this computer and control it"
	if viewOnly {
		what = "view this screen"
	}
	return technician + " wants to " + what + " with RMMZit remote desktop. Allow it?"
}
