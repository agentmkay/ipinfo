package ipinfo_test

import (
	"fmt"
	"testing"

	"github.com/agentmkay/ipinfo"
)

func ExampleLookup() {
	details, err := ipinfo.Lookup("8.8.8.8")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	for _, d := range details {
		fmt.Printf("IP: %s\n", d.IP)
		fmt.Printf("Version: %s\n", d.Version)
		fmt.Printf("Private: %v\n", d.IsPrivate)
		fmt.Printf("Common Uses: %v\n", d.CommonUses)
	}
	// Output:
	// IP: 8.8.8.8
	// Version: IPv4
	// Private: false
	// Common Uses: [Public address]
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"Valid IPv4", "8.8.8.8", false},
		{"Valid IPv6", "::1", false},
		{"Valid Hostname", "localhost", false},
		{"Invalid IP", "999.999.999.999", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ipinfo.Lookup(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("Lookup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
