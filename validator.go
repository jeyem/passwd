package passwd

import (
	"fmt"
	"unicode"
)

const (
	UppercaseCharacter = `uppercase`
	LowercaseCharacter = `lowercase`
	NumberCharacter    = `number`
	SymbolCharacter    = `symbol`
)

func Valid(saltPassword string, minLength int, chars ...string) error {
	if len(saltPassword) <= minLength {
		return fmt.Errorf("password length is less than %d", minLength)
	}
	exists := map[string]bool{}
	for _, c := range saltPassword {
		switch {
		case unicode.IsUpper(c):
			exists[UppercaseCharacter] = true
		case unicode.IsLower(c):
			exists[LowercaseCharacter] = true
		case unicode.IsNumber(c):
			exists[NumberCharacter] = true
		case unicode.IsSymbol(c):
			exists[SymbolCharacter] = true
		}
	}

	for _, c := range chars {
		if _, ok := exists[c]; !ok {
			return fmt.Errorf("password must contains %s character", c)
		}
	}

	return nil
}
