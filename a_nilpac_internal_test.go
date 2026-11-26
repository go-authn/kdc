package kdc

import "testing"

// A Config with no PAC is valid. This file sorts first in the package so that,
// were the nil check lost, the assertion here is the first failure rather than
// a nil dereference somewhere else.
func TestANilPACConfigIsValid(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("checkPAC: a runtime error escaped: %v", r)
		}
	}()
	c := &Config{}
	if err := c.checkPAC(); err != nil {
		t.Error(err)
	}
}
