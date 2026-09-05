// Package firmware validates reported UniFi compatibility versions. It neither
// selects a protocol profile nor implements firmware installation.
package firmware

import (
	"strconv"
	"strings"
)

// ValidVersion accepts canonical 3/4-component decimal versions. It deliberately
// imposes no ordering: the controller may select a lower version on another channel.
func ValidVersion(value string) bool {
	if len(value) > 43 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 && len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 10 || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, ch := range []byte(part) {
			if ch < '0' || ch > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
