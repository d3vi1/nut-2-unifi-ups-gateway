package nut

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// parseLine tokenizes one NUT protocol response. The protocol only escapes a
// quote or a backslash inside quoted strings; accepting other escapes would
// silently reinterpret malformed upstream data.
func parseLine(line string) ([]string, error) {
	if !utf8.ValidString(line) {
		return nil, errors.New("invalid UTF-8")
	}
	tokens := make([]string, 0, 4)
	for position := 0; ; {
		for position < len(line) && (line[position] == ' ' || line[position] == '\t') {
			position++
		}
		if position == len(line) {
			return tokens, nil
		}

		if line[position] == '"' {
			position++
			var value strings.Builder
			closed := false
			for position < len(line) {
				character := line[position]
				position++
				switch character {
				case '"':
					closed = true
				case '\\':
					if position >= len(line) || (line[position] != '\\' && line[position] != '"') {
						return nil, errors.New("invalid quoted escape")
					}
					value.WriteByte(line[position])
					position++
				case '\r', '\n', 0:
					return nil, errors.New("control character in quoted token")
				default:
					value.WriteByte(character)
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, errors.New("unterminated quoted token")
			}
			if position < len(line) && line[position] != ' ' && line[position] != '\t' {
				return nil, errors.New("missing separator after quoted token")
			}
			tokens = append(tokens, value.String())
			continue
		}

		start := position
		for position < len(line) && line[position] != ' ' && line[position] != '\t' {
			if line[position] == '"' || line[position] == '\r' || line[position] == '\n' || line[position] == 0 {
				return nil, errors.New("invalid unquoted token")
			}
			position++
		}
		if position == start {
			return nil, errors.New("empty unquoted token")
		}
		tokens = append(tokens, line[start:position])
	}
}
