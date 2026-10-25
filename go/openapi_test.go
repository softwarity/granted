package granted

import (
	"encoding/json"
	"net/http"
	"testing"
)

// security renders a Description's Security as JSON, to compare with what
// nestjs-granted writes for the same rule.
func security(t *testing.T, d Description) string {
	t.Helper()
	out, err := json.Marshal(d.Security)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		name      string
		scheme    string
		specs     []Spec
		security  string
		forbidden string
	}{
		{
			name:      "one role",
			specs:     []Spec{HasRole("USER")},
			security:  `[{"bearer":["USER"]}]`,
			forbidden: "Forbidden unless: hasRole(USER)",
		},
		{
			name:      "or gives entries, and gives the roles of one entry — several specs are an and",
			specs:     []Spec{Or(HasRole("ADMIN"), And(HasRole("MANAGER"), HasRole("AUDIT"))), HasRole("USER")},
			security:  `[{"bearer":["ADMIN","USER"]},{"bearer":["MANAGER","AUDIT","USER"]}]`,
			forbidden: "Forbidden unless: (hasRole(ADMIN) or (hasRole(MANAGER) and hasRole(AUDIT))) and hasRole(USER)",
		},
		{
			name:      "a branch with no role is an authenticated caller",
			specs:     []Spec{Or(HasRole("ADMIN"), IsUser(Param, "id"))},
			security:  `[{"bearer":["ADMIN"]},{"bearer":[]}]`,
			forbidden: "Forbidden unless: hasRole(ADMIN) or isUser(Param, id)",
		},
		{
			name:      "not of a role reduces to authenticated",
			specs:     []Spec{IsAuthenticated(), Not(HasRole("GUEST"))},
			security:  `[{"bearer":[]}]`,
			forbidden: "Forbidden unless: isAuthenticated() and not(hasRole(GUEST))",
		},
		{
			name:      "not of a combination keeps its label whole",
			specs:     []Spec{Not(Or(HasRole("GUEST"), HasRole("BANNED")))},
			security:  `[{"bearer":[]}]`,
			forbidden: "Forbidden unless: not(hasRole(GUEST) or hasRole(BANNED))",
		},
		{
			name:     "isTrue is an anonymous caller: no 403",
			specs:    []Spec{IsTrue()},
			security: `[{}]`,
		},
		{
			name:     "an or with isTrue lets an anonymous caller through",
			specs:    []Spec{Or(HasRole("ADMIN"), IsTrue())},
			security: `[{"bearer":["ADMIN"]},{}]`,
		},
		{
			name:      "isFalse writes no security",
			specs:     []Spec{IsFalse()},
			security:  `null`,
			forbidden: "Forbidden unless: isFalse()",
		},
		{
			name:      "a spec built by hand reads as authenticated, labelled by its ID",
			specs:     []Spec{{ID: "isWeekday()", Check: func(*http.Request, *Caller) bool { return true }}},
			security:  `[{"bearer":[]}]`,
			forbidden: "Forbidden unless: isWeekday()",
		},
		{
			name:      "the same entry is written once",
			specs:     []Spec{Or(HasRole("ADMIN"), HasRole("ADMIN"), IsAuthenticated(), IsTenant(Param, "tenant"))},
			security:  `[{"bearer":["ADMIN"]},{"bearer":[]}]`,
			forbidden: "Forbidden unless: hasRole(ADMIN) or hasRole(ADMIN) or isAuthenticated() or isTenant(Param, tenant)",
		},
		{
			name:     "no spec: open, as Require has it",
			security: `[{}]`,
		},
		{
			name:      "under the scheme named",
			scheme:    "jwt",
			specs:     []Spec{Or(HasRole("ADMIN"), IsUser(Param, "id"))},
			security:  `[{"jwt":["ADMIN"]},{"jwt":[]}]`,
			forbidden: "Forbidden unless: hasRole(ADMIN) or isUser(Param, id)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Describe(c.scheme, c.specs...)
			if got := security(t, d); got != c.security {
				t.Errorf("security %s, want %s", got, c.security)
			}
			if d.Forbidden != c.forbidden {
				t.Errorf("forbidden %q, want %q", d.Forbidden, c.forbidden)
			}
		})
	}

	t.Run("a Description's roles are its own", func(t *testing.T) {
		rule := And(HasRole("A"), HasRole("B"))
		Describe("", rule).Security[0]["bearer"][0] = "Z"
		if got := security(t, Describe("", rule)); got != `[{"bearer":["A","B"]}]` {
			t.Fatal(got)
		}
	})
}
