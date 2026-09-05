package firmware

import "testing"

func TestValidVersion(t *testing.T) {
	for _, v := range []string{"0.0.0", "1.6.4.432", "1.4.12", "4294967295.2.3"} {
		if !ValidVersion(v) {
			t.Fatal("valid version rejected")
		}
	}
	for _, v := range []string{"", "1.2", "1.2.3.4.5", "1.2.3-beta", "1.2.3\n", "01.2.3", "+1.2.3", "１.2.3", "1．2.3", "4294967296.2.3"} {
		if ValidVersion(v) {
			t.Fatal("invalid version accepted")
		}
	}
}
