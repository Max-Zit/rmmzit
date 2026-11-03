// Package rmmzit holds the license texts that the programs carry with them
// ("rmmzit-agent licenses", "rmmzit-server -licenses"): a program copied
// alone to a computer still has its license and the notices of the
// libraries built into it.
package rmmzit

import _ "embed"

// License is the GNU AGPLv3 under which RMMZit is published.
//
//go:embed LICENSE
var License string

// ThirdPartyLicenses lists the libraries built into the programs with their
// licenses (written by tools/licenses during the release build).
//
//go:embed THIRD_PARTY_LICENSES.md
var ThirdPartyLicenses string

// Notices is what the programs print: the license, then the libraries'.
func Notices() string {
	return "RMMZit — free software under the GNU Affero General Public License v3.\n" +
		"Source code: https://github.com/Max-Zit/rmmzit\n\n" + License + "\n\n" + ThirdPartyLicenses
}
