package granted

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"reflect"
	"strconv"
	"strings"
)

// ClaimType is what [Claim] and [Claims] convert a claim to.
type ClaimType interface {
	~string | ~bool | ~int | ~int64 | ~float64
}

// RawClaim returns a claim of the caller as found: a value of the verified JWT
// (dotted paths for nested claims, e.g. `realm_access.territories`), or the
// header of that name with the header provider — never a header when the
// identity comes from a JWT. Nil when absent.
//
// Roles decide which actions a caller may take; claims scope which data.
func RawClaim(ctx context.Context, name string) any {
	c := FromContext(ctx)
	if c == nil || c.claim == nil {
		return nil
	}
	return c.claim(name)
}

// Claim returns the claim name converted to T, and whether it was there with
// that type. A string is converted strictly: `"5000"` is a number, `"true"` /
// `"false"` a boolean. A value of another type — a list where one value is
// expected included — reads as absent, with a warning naming the claim, never
// its value.
func Claim[T ClaimType](ctx context.Context, name string) (T, bool) {
	return claimOf[T](FromContext(ctx), name)
}

// Claims returns the list claim name, each element converted to T. A string is
// parsed: a JSON array (`["FR","GP"]`), or a comma-separated list (`FR, GP`);
// a single value is a list of one. The elements of another type are dropped,
// with a warning naming the claim, never the values. Absent gives an empty
// list, never nil — ready for an `IN (...)`.
//
//	territories := granted.Claims[string](r.Context(), "territories")
func Claims[T ClaimType](ctx context.Context, name string) []T {
	return claimsOf[T](FromContext(ctx), name)
}

func claimOf[T ClaimType](c *Caller, name string) (T, bool) {
	var zero T
	if c == nil || c.claim == nil {
		return zero, false
	}
	raw := c.claim(name)
	if absent(raw) {
		return zero, false
	}
	if isList(raw) {
		c.invalidClaim(name, typeName[T]())
		return zero, false
	}
	value, ok := convert[T](raw)
	if !ok {
		c.invalidClaim(name, typeName[T]())
		return zero, false
	}
	return value, true
}

func claimsOf[T ClaimType](c *Caller, name string) []T {
	out := []T{}
	if c == nil || c.claim == nil {
		return out
	}
	raw := c.claim(name)
	if absent(raw) {
		return out
	}
	var list []any
	switch v := raw.(type) {
	case string:
		parsed, ok := parseList(v)
		if !ok {
			c.invalidClaim(name, typeName[T]()+"[]")
			return out
		}
		list = parsed
	case []any:
		list = v
	case []string:
		for _, item := range v {
			list = append(list, item)
		}
	default:
		list = []any{raw}
	}
	for _, item := range list {
		if value, ok := convert[T](item); ok {
			out = append(out, value)
		}
	}
	dropped := len(list) - len(out)
	switch {
	case dropped > 0 && len(out) == 0:
		// Nothing left of a list that had elements: as invalid as a single value of the wrong type.
		c.invalidClaim(name, typeName[T]()+"[]")
	case dropped > 0:
		// Never log the values: they come from the caller's token or headers.
		c.logger.Warn("claim '"+name+"': "+strconv.Itoa(dropped)+" element(s) not of the expected type ("+typeName[T]()+") ignored", slog.String("claim", name))
	}
	return out
}

func (c *Caller) invalidClaim(name, expected string) {
	c.logger.Warn("claim '"+name+"' is not of the expected type ("+expected+"): ignored", slog.String("claim", name))
}

func absent(raw any) bool {
	return raw == nil || raw == ""
}

func isList(raw any) bool {
	switch raw.(type) {
	case []any, []string:
		return true
	}
	return false
}

// convert converts one value to T: as is when it already has that type, from
// a string strictly, never from anything else.
func convert[T ClaimType](value any) (T, bool) {
	var out T
	target := reflect.ValueOf(&out).Elem()
	switch target.Kind() {
	case reflect.String:
		s, ok := value.(string)
		if !ok {
			return out, false
		}
		target.SetString(s)
	case reflect.Bool:
		switch v := value.(type) {
		case bool:
			target.SetBool(v)
		case string:
			if v != "true" && v != "false" {
				return out, false
			}
			target.SetBool(v == "true")
		default:
			return out, false
		}
	case reflect.Float64:
		n, ok := number(value)
		if !ok {
			return out, false
		}
		target.SetFloat(n)
	case reflect.Int, reflect.Int64:
		n, ok := number(value)
		if !ok || n != math.Trunc(n) || n > math.MaxInt64 || n < math.MinInt64 {
			return out, false
		}
		target.SetInt(int64(n))
	default:
		return out, false
	}
	return out, true
}

func number(value any) (float64, bool) {
	var n float64
	switch v := value.(type) {
	case float64:
		n = v
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, false
		}
		n = parsed
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		n = parsed
	default:
		return 0, false
	}
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, false
	}
	return n, true
}

// typeName is how the warnings name T — the names the other implementations use.
func typeName[T ClaimType]() string {
	var zero T
	switch reflect.TypeOf(zero).Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	default:
		return "number"
	}
}
