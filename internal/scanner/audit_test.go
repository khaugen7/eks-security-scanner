package scanner

import (
    "reflect"
    "testing"
)

// ----------------------------------------------------------------
// 1) Pure-function tests
// ----------------------------------------------------------------

func TestExtractRoleName(t *testing.T) {
    cases := []struct {
        arn  string
        want string
    }{
        {"arn:aws:iam::123456789012:role/MyRole", "MyRole"},
        {"arn:aws:iam::123456789012:role/path/to/RoleName", "RoleName"},
        {"arn:aws:iam::123456789012:role/", ""},
        {"just-a-role-name", "just-a-role-name"},
    }
    for _, c := range cases {
        if got := extractRoleName(c.arn); got != c.want {
            t.Errorf("extractRoleName(%q) = %q; want %q", c.arn, got, c.want)
        }
    }
}

func TestNormalizeStringOrSlice(t *testing.T) {
    // single string
    if got := normalizeStringOrSlice("foo"); !reflect.DeepEqual(got, []string{"foo"}) {
        t.Errorf("normalizeStringOrSlice(\"foo\") = %v; want [\"foo\"]", got)
    }
    // slice of interface{}
    in := []interface{}{"a", "b", 123}
    want := []string{"a", "b"}
    if got := normalizeStringOrSlice(in); !reflect.DeepEqual(got, want) {
        t.Errorf("normalizeStringOrSlice(%v) = %v; want %v", in, got, want)
    }
    // anything else
    if got := normalizeStringOrSlice(42); got != nil {
        t.Errorf("normalizeStringOrSlice(42) = %v; want nil", got)
    }
}

func TestIsOverlyPermissive(t *testing.T) {
    safePolicy := `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::bucket/key"]}]}`
    wildcardAction := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket/*"}]}`
    wildcardService := `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`
    malformed := `not-json`

    cases := []struct {
        name     string
        policy   string
        expected bool
    }{
        {"safe", safePolicy, false},
        {"wildcard-action", wildcardAction, true},
        {"service-wide", wildcardService, true},
        {"malformed", malformed, false},
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            if got := isOverlyPermissive(c.policy); got != c.expected {
                t.Errorf("isOverlyPermissive(%s) = %v; want %v", c.name, got, c.expected)
            }
        })
    }
}
