package passwd

import "testing"

const (
	tmpPass = "12345678abcd@#"
)

func TestModule(t *testing.T) {
	created := Make(tmpPass)

	if !Check(tmpPass, created) {
		t.Error("must pass check correct password")
	}

	if Check("!"+tmpPass, created) {
		t.Error("must not pass check wrong password")
	}

}
