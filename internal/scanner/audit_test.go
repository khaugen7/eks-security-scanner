package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// helper to load a testdata file
func loadTestData(t *testing.T, name string) string {
    t.Helper()
    b, err := os.ReadFile(filepath.Join("testdata", name))
    if err != nil {
        t.Fatalf("failed to read %s: %v", name, err)
    }
    return string(b)
}

func TestParseMapRoles(t *testing.T) {
    data := loadTestData(t, "map_roles.yaml")
    roles := ParseMapRoles(data)

    if len(roles) != 2 {
        t.Fatalf("expected 2 roles, got %d", len(roles))
    }

    want := AWSAuthRole{
        RoleARN:  "arn:aws:iam::123456789012:role/readonly",
        Username: "readonly",
        Groups:   []string{"view"},
    }
    if !reflect.DeepEqual(roles[0], want) {
        t.Errorf("first role = %+v; want %+v", roles[0], want)
    }

    // ensure we pick up the system:masters on the second
    if !contains(roles[1].Groups, "system:masters") {
        t.Errorf("expected second role to have 'system:masters' but got %v", roles[1].Groups)
    }
}

func TestParseMapUsers(t *testing.T) {
    data := loadTestData(t, "map_users.yaml")
    users := ParseMapUsers(data)

    if len(users) != 2 {
        t.Fatalf("expected 2 users, got %d", len(users))
    }

    want := AWSAuthUser{
        UserARN:  "arn:aws:iam::123456789012:user/john",
        Username: "john",
        Groups:   []string{"developers"},
    }
    if !reflect.DeepEqual(users[0], want) {
        t.Errorf("first user = %+v; want %+v", users[0], want)
    }

    if !contains(users[1].Groups, "system:masters") {
        t.Errorf("expected second user to have 'system:masters' but got %v", users[1].Groups)
    }
}

// captureStdout captures whatever f() prints to stdout.
func captureStdout(f func()) string {
    old := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w

    f()

    w.Close()
    os.Stdout = old
    var buf bytes.Buffer
    io.Copy(&buf, r)
    return buf.String()
}

func TestPrintIAMBindings(t *testing.T) {
    roles := []AWSAuthRole{
        {RoleARN: "r1", Username: "u1", Groups: []string{"g1"}},
    }
    users := []AWSAuthUser{
        {UserARN: "u1", Username: "usr1", Groups: []string{"g2"}},
    }

    out := captureStdout(func() {
        PrintIAMBindings(roles, users)
    })
	fmt.Print(out)

    if !strings.Contains(out, "IAM Role Bindings:") {
        t.Error("missing IAM Role Bindings header")
    }
    if !strings.Contains(out, "- r1 -> u1 [g1]") {
        t.Error("did not print expected role line")
    }
    if !strings.Contains(out, "IAM User Bindings:") {
        t.Error("missing IAM User Bindings header")
    }
    if !strings.Contains(out, "- u1 -> usr1 [g2]") {
        t.Error("did not print expected user line")
    }
}

func TestFindOverprivilegedIdentities(t *testing.T) {
    roles := []AWSAuthRole{
        {RoleARN: "r1", Username: "u1", Groups: []string{"system:masters", "g1"}},
        {RoleARN: "r2", Username: "u2", Groups: []string{"g2"}},
    }
    users := []AWSAuthUser{
        {UserARN: "u1", Username: "usr1", Groups: []string{"g2"}},
        {UserARN: "u2", Username: "usr2", Groups: []string{"system:masters"}},
    }

    out := captureStdout(func() {
        FindOverprivilegedIdentities(roles, users)
    })

    lines := strings.Split(out, "\n")
    // should see exactly two entries (one ROLE, one USER)
    var found []string
    for _, l := range lines {
        if strings.HasPrefix(l, "ROLE:") || strings.HasPrefix(l, "USER:") {
            found = append(found, l)
        }
    }
    if len(found) != 2 {
        t.Fatalf("expected 2 overprivileged entries, got %d:\n%v", len(found), found)
    }
    if !strings.Contains(found[0], "r1") {
        t.Errorf("first overprivileged role line = %s", found[0])
    }
    if !strings.Contains(found[1], "USER: u2") {
        t.Errorf("second overprivileged user line = %s", found[1])
    }
}

// simple helper
func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func TestExtractRoleName(t *testing.T) {
    cases := []struct {
        arn  string
        want string
    }{
        {
            arn:  "arn:aws:iam::123456789012:role/MyRole",
            want: "MyRole",
        },
        {
            arn:  "arn:aws:iam::123456789012:role/path/to/RoleName",
            want: "RoleName",
        },
        {
            arn:  "arn:aws:iam::123456789012:role/",
            want: "",
        },
        {
            arn:  "just-a-role-name",
            want: "just-a-role-name",
        },
    }

    for _, c := range cases {
        got := extractRoleName(c.arn)
        if got != c.want {
            t.Errorf("extractRoleName(%q) = %q; want %q", c.arn, got, c.want)
        }
    }
}

func TestNormalizeStringOrSlice(t *testing.T) {
    // string case
    if got := normalizeStringOrSlice("foo"); !reflect.DeepEqual(got, []string{"foo"}) {
        t.Errorf("normalizeStringOrSlice(string) = %v; want [\"foo\"]", got)
    }

    // slice of interface{}
    inSlice := []interface{}{"a", "b", 123, true}
    want := []string{"a", "b"}
    if got := normalizeStringOrSlice(inSlice); !reflect.DeepEqual(got, want) {
        t.Errorf("normalizeStringOrSlice([]interface{}) = %v; want %v", got, want)
    }

    // completely unknown type
    if got := normalizeStringOrSlice(42); got != nil {
        t.Errorf("normalizeStringOrSlice(unknown) = %v; want nil", got)
    }
}

func TestIsOverlyPermissive(t *testing.T) {
    cases := []struct {
        name     string
        policy   string
        expected bool
    }{
        {
            name: "wildcard action",
            policy: `{
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "arn:aws:s3:::my-bucket/*"
                    }
                ]
            }`,
            expected: true,
        },
        {
            name: "service-wide action",
            policy: `{
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::my-bucket/*"
                    }
                ]
            }`,
            expected: true,
        },
        {
            name: "wildcard resource",
            policy: `{
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "*"
                    }
                ]
            }`,
            expected: true,
        },
        {
            name: "specific permissions only",
            policy: `{
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["ec2:DescribeInstances", "ec2:StartInstances"],
                        "Resource": ["arn:aws:ec2:us-west-2:123456789012:instance/*"]
                    },
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }`,
            expected: false,
        },
        {
            name: "malformed JSON",
            policy: `not-a-json`,
            expected: false,
        },
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            got := isOverlyPermissive(c.policy)
            if got != c.expected {
                t.Errorf("isOverlyPermissive(%q) = %v; want %v", c.name, got, c.expected)
            }
        })
    }
}
