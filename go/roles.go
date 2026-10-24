package granted

import (
	"encoding/json"
	"strings"
)

// resolveRoles expands roles with the roles they imply, transitively, then
// keeps only the known ones when known is set. Expand first, filter second:
// list in known the implied roles too. Never nil.
func resolveRoles(roles []string, hierarchy map[string][]string, known []string) []string {
	seen := map[string]bool{}
	resolved := []string{}
	stack := []string{}
	add := func(role string) {
		if !seen[role] {
			seen[role] = true
			resolved = append(resolved, role)
			stack = append(stack, role)
		}
	}
	for _, role := range roles {
		add(role)
	}
	for len(stack) > 0 {
		role := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, implied := range hierarchy[role] {
			add(implied)
		}
	}
	if known == nil {
		return resolved
	}
	keep := map[string]bool{}
	for _, role := range known {
		keep[role] = true
	}
	filtered := []string{}
	for _, role := range resolved {
		if keep[role] {
			filtered = append(filtered, role)
		}
	}
	return filtered
}

// parseList reads a list carried by a string: a JSON array when it starts with
// `[` (ok is false when it doesn't parse), a comma-separated list otherwise.
func parseList(raw string) (list []any, ok bool) {
	if strings.HasPrefix(strings.TrimSpace(raw), "[") {
		if json.Unmarshal([]byte(raw), &list) != nil {
			return nil, false
		}
		return list, true
	}
	list = []any{}
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list, true
}

// stringsOf keeps the strings of a list claim — a JSON array, or a string
// parsed by [parseList] — dropping anything else.
func stringsOf(value any) []string {
	var list []any
	switch v := value.(type) {
	case []any:
		list = v
	case []string:
		return v
	case string:
		list, _ = parseList(v)
	}
	out := []string{}
	for _, item := range list {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
