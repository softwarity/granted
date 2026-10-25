package granted

import (
	"slices"
	"strings"
)

// Description is how a route's specs read in an OpenAPI document — what
// nestjs-granted writes for `@GrantedTo`. granted depends on no router nor
// OpenAPI library: the host copies it onto the operation it documents.
type Description struct {
	// Security is the operation's `security`: its entries are alternatives
	// (or), the roles of one entry are all required (and).
	// `Or(HasRole("A"), And(HasRole("B"), HasRole("C")))` gives
	// `[{bearer: [A]}, {bearer: [B, C]}]`. A branch with no role ([IsUser],
	// [IsAuthenticated], a spec built by hand…) gives `{bearer: []}`, an
	// authenticated caller; [IsTrue] gives `{}`, an anonymous one. Nil when no
	// caller passes ([IsFalse]): an empty `security` would mean "open".
	Security []map[string][]string
	// Forbidden describes the operation's 403 response, the rule in clear:
	// `Forbidden unless: hasRole(A) or (hasRole(B) and hasRole(C))`. Empty when
	// an anonymous caller gets through anyway: there is no 403 to document.
	Forbidden string
}

// Describe describes the specs given to [Granted.Require] — several specs are
// all required, as Require has them — under the security scheme named scheme
// (`bearer` when empty), the name the document's `components.securitySchemes`
// declares.
//
//	rule := []granted.Spec{granted.HasRole("ADMIN")}
//	mux.Handle("DELETE /orders/{id}", g.Require(rule...)(deleteOrder))
//	d := granted.Describe("", rule...)
//	operation.Security, operation.Responses["403"] = d.Security, Response{Description: d.Forbidden}
func Describe(scheme string, specs ...Spec) Description {
	if scheme == "" {
		scheme = "bearer"
	}
	var d Description
	var seen []alternative
	anonymous := false
	for _, alt := range andAlternatives(specs) {
		if slices.ContainsFunc(seen, func(other alternative) bool { return sameAlternative(alt, other) }) {
			continue
		}
		seen = append(seen, alt)
		if alt == nil {
			anonymous = true
			d.Security = append(d.Security, map[string][]string{})
			continue
		}
		d.Security = append(d.Security, map[string][]string{scheme: slices.Clone(alt)})
	}
	if !anonymous {
		d.Forbidden = "Forbidden unless: " + joinLabels(specs, "and")
	}
	return d
}

// alternative is the roles one way through a rule requires; nil for an
// anonymous caller, empty for an authenticated one.
type alternative []string

type description struct {
	alternatives []alternative
	label        string
	// Combines several specs: wrapped in parentheses inside another combination.
	compound bool
}

func descriptionOf(spec Spec) description {
	if spec.description == nil {
		return description{alternatives: []alternative{{}}, label: spec.ID}
	}
	return *spec.description
}

// joinLabels joins the labels of specs with operator; a combination inside is
// wrapped in parentheses.
func joinLabels(specs []Spec, operator string) string {
	labels := make([]string, len(specs))
	for i, spec := range specs {
		d := descriptionOf(spec)
		labels[i] = d.label
		if d.compound && len(specs) > 1 {
			labels[i] = "(" + d.label + ")"
		}
	}
	return strings.Join(labels, " "+operator+" ")
}

// andAlternatives combines every alternative of each spec with every
// alternative of the others.
func andAlternatives(specs []Spec) []alternative {
	combined := []alternative{nil}
	for _, spec := range specs {
		var next []alternative
		for _, left := range combined {
			for _, right := range descriptionOf(spec).alternatives {
				switch {
				case left == nil:
					next = append(next, right)
				case right == nil:
					next = append(next, left)
				default:
					merged := slices.Clone(left)
					for _, role := range right {
						if !slices.Contains(merged, role) {
							merged = append(merged, role)
						}
					}
					next = append(next, merged)
				}
			}
		}
		combined = next
	}
	return combined
}

func orAlternatives(specs []Spec) []alternative {
	var out []alternative
	for _, spec := range specs {
		out = append(out, descriptionOf(spec).alternatives...)
	}
	return out
}

func sameAlternative(a, b alternative) bool {
	return (a == nil) == (b == nil) && slices.Equal(a, b)
}
