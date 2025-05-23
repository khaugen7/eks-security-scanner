package scanner

import (
	"strings"
	"testing"

	"github.com/khaugen7/eks-security-scanner/internal/testhelpers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSelectorMatches(t *testing.T) {
	sel := map[string]string{"app": "foo", "tier": "backend"}
	good := map[string]string{"app": "foo", "tier": "backend", "x": "y"}
	if !selectorMatches(sel, good) {
		t.Error("expected selectorMatches to return true")
	}
	if selectorMatches(sel, map[string]string{"app": "foo"}) {
		t.Error("expected false when missing a key")
	}
	if selectorMatches(sel, map[string]string{"app": "bar", "tier": "backend"}) {
		t.Error("expected false when value differs")
	}
}

func TestFormatNode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pod/ns/p", "[POD] ns/p"},
		{"svc/ns/s", "[SVC] ns/s"},
		{"ep/ns/1.2.3.4", "[EP]  ns/1.2.3.4"},
		{"sa/ns/sa", "[SA]  ns/sa"},
		{"iam-role/X", "[IAM] X"},
		{"foo/bar", "foo/bar"},
	}
	for _, c := range cases {
		if got := formatNode(c.in); got != c.want {
			t.Errorf("formatNode(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestPrintDOTGraph(t *testing.T) {
	edges := []GraphEdge{{From: "pod/ns/p", To: "sa/ns/sa", Label: "uses"}}
	out := testhelpers.CaptureOutput(func() { PrintDOTGraph(edges) })
	if !strings.Contains(out, "digraph eks_threat_graph") {
		t.Error("missing DOT header")
	}
	if !strings.Contains(out, `"pod/ns/p" -> "sa/ns/sa" [label="uses"];`) {
		t.Error("missing our edge line")
	}
}

func TestPrintASCIIGraph(t *testing.T) {
	edges := []GraphEdge{
		{From: "pod/ns/p", To: "svc/ns/s", Label: "matches"},
		{From: "svc/ns/s", To: "ep/ns/1.2.3.4", Label: "routes-to"},
	}
	out := testhelpers.CaptureOutput(func() { PrintASCIIGraph(edges) })
	if !strings.Contains(out, "Threat Graph (ASCII Format):") {
		t.Error("missing ASCII header")
	}
	if !strings.Contains(out, "[POD] ns/p") ||
		!strings.Contains(out, "└─[matches]→ [SVC] ns/s") {
		t.Error("missing pod→svc line")
	}
	if !strings.Contains(out, "[SVC] ns/s") ||
		!strings.Contains(out, "└─[routes-to]→ [EP]  ns/1.2.3.4") {
		t.Error("missing svc→ep line")
	}
}

func TestRunGraphCheck_ASCII(t *testing.T) {
	// Build a fake clientset: SA with annotation, Pod, Service, Endpoints
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "mysa",
			Namespace:   "ns1",
			Annotations: map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/RoleA"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1", Labels: map[string]string{"app": "x"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "mysa", Containers: []corev1.Container{{Name: "c", Image: "i"}}},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "x"}},
	}
	eps := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}},
	}

	var client kubernetes.Interface = fake.NewSimpleClientset(sa, pod, svc, eps)
	out := testhelpers.CaptureOutput(func() { RunGraphCheck("ascii", "ns1", client) })

	// Pod→SA
	if !strings.Contains(out, "[POD] ns1/pod1") ||
		!strings.Contains(out, "└─[uses]→ [SA]  ns1/mysa") {
		t.Error("pod→sa edge missing")
	}
	// SA→IAM
	if !strings.Contains(out, "[SA]  ns1/mysa") ||
		!strings.Contains(out, "└─[assumes]→ [IAM] RoleA") {
		t.Error("sa→iam edge missing")
	}
	// Pod→Svc
	if !strings.Contains(out, "└─[matches]→ [SVC] ns1/svc1") {
		t.Error("pod→svc edge missing")
	}
	// Svc→Ep
	if !strings.Contains(out, "└─[routes-to]→ [EP]  ns1/10.0.0.1") {
		t.Error("svc→ep edge missing")
	}
}

func TestRunGraphCheck_DOT(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "mysa",
			Namespace:   "ns1",
			Annotations: map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/RoleA"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1", Labels: map[string]string{"app": "x"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "mysa", Containers: []corev1.Container{{Name: "c", Image: "i"}}},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "x"}},
	}
	eps := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
		Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}},
	}

	var client kubernetes.Interface = fake.NewSimpleClientset(sa, pod, svc, eps)
	out := testhelpers.CaptureOutput(func() { RunGraphCheck("dot", "ns1", client) })

	if !strings.Contains(out, "digraph eks_threat_graph") {
		t.Error("missing dot graph header")
	}
	if !strings.Contains(out, `"pod/ns1/pod1" -> "sa/ns1/mysa" [label="uses"];`) {
		t.Error("missing uses edge")
	}
}
