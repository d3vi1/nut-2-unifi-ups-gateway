package releaseguard

import "testing"

func TestManagedBundleTemplatesCannotBeMissingOrModified(t *testing.T) {
	release := loadTestContext(t, validEnvironment())
	binding := mustTestBinding(t, release)
	root := "nut-2-unifi-ups-gateway-" + release.Tag + "-compose/"
	for _, name := range []string{"compose.managed.yaml", "compose.managed-nut-host.yaml"} {
		for _, operation := range []string{"missing", "changed"} {
			t.Run(name+"/"+operation, func(t *testing.T) {
				bundle := makeTestComposeBundle(t, release, binding, func(members map[string]testBundleMember) {
					if operation == "missing" {
						delete(members, root+name)
						return
					}
					m := members[root+name]
					m.data = append(m.data, []byte("\n# unreviewed change\n")...)
					members[root+name] = m
				})
				if verifyComposeBundle(release, binding, bundle) == nil {
					t.Fatal("unsealed managed template accepted")
				}
			})
		}
	}
}
