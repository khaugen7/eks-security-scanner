package scanner

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// captureOutput captures stdout from f()
func captureOutput(f func()) string {
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

func TestHasResourceQuota(t *testing.T) {
	// No ResourceQuota
	client := fake.NewSimpleClientset()
	if hasResourceQuota("ns1", client) {
		t.Error("expected hasResourceQuota=false when none exist")
	}

	// With one ResourceQuota
	rq := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rq1",
			Namespace: "ns1",
		},
	}
	client2 := fake.NewSimpleClientset(rq)
	if !hasResourceQuota("ns1", client2) {
		t.Error("expected hasResourceQuota=true when a ResourceQuota exists")
	}
}

func TestHasLimitRange(t *testing.T) {
	client := fake.NewSimpleClientset()
	if hasLimitRange("ns1", client) {
		t.Error("expected hasLimitRange=false when none exist")
	}

	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lr1",
			Namespace: "ns1",
		},
	}
	client2 := fake.NewSimpleClientset(lr)
	if !hasLimitRange("ns1", client2) {
		t.Error("expected hasLimitRange=true when a LimitRange exists")
	}
}

func TestDefaultSAUsed(t *testing.T) {
	// default SA with no secrets/annotations/pullSecrets
	sa1 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "ns1",
		},
	}
	client1 := fake.NewSimpleClientset(sa1)
	if defaultSAUsed("ns1", client1) {
		t.Error("expected defaultSAUsed=false when SA has no extra fields")
	}

	// default SA with a secret
	sa2 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "ns1",
		},
		Secrets: []corev1.ObjectReference{{Name: "s1"}},
	}
	client2 := fake.NewSimpleClientset(sa2)
	if !defaultSAUsed("ns1", client2) {
		t.Error("expected defaultSAUsed=true when SA has a Secret")
	}

	// default SA with annotation
	sa3 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "default",
			Namespace:   "ns1",
			Annotations: map[string]string{"foo": "bar"},
		},
	}
	client3 := fake.NewSimpleClientset(sa3)
	if !defaultSAUsed("ns1", client3) {
		t.Error("expected defaultSAUsed=true when SA has an Annotation")
	}
}

func TestCheckDefaultSARoleBindings(t *testing.T) {
	// no bindings
	client := fake.NewSimpleClientset()
	findings := checkDefaultSARoleBindings("ns1", client)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}

	// one high, one med
	rbHigh := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rb1",
			Namespace: "ns1",
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "default",
			Namespace: "ns1",
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "cluster-admin",
		},
	}
	rbMed := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rb2",
			Namespace: "ns1",
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "default",
			Namespace: "ns1",
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "edit",
		},
	}
	client2 := fake.NewSimpleClientset(rbHigh, rbMed)
	findings2 := checkDefaultSARoleBindings("ns1", client2)
	if len(findings2) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings2))
	}
	if findings2[0].Severity != "HIGH" ||
		!strings.Contains(findings2[0].Message, "cluster-admin") {
		t.Errorf("first finding incorrect: %+v", findings2[0])
	}
	if findings2[1].Severity != "MED" ||
		!strings.Contains(findings2[1].Message, "edit") {
		t.Errorf("second finding incorrect: %+v", findings2[1])
	}
}

func TestRunNamespaceCheck_AllFindings(t *testing.T) {
	// Build fake client with no RQ, no LR, default SA used, plus 2 RoleBindings
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "ns1",
		},
		Secrets: []corev1.ObjectReference{{Name: "s1"}},
	}
	rbHigh := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rb1",
			Namespace: "ns1",
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "default",
			Namespace: "ns1",
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "cluster-admin",
		},
	}
	rbMed := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rb2",
			Namespace: "ns1",
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "default",
			Namespace: "ns1",
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "edit",
		},
	}

	var client kubernetes.Interface = fake.NewSimpleClientset(sa, rbHigh, rbMed)

	out := captureOutput(func() {
		RunNamespaceCheck("ns1", client)
	})

	// Initial MEDs
	if !strings.Contains(out, "[MED]  Namespace ns1 has no ResourceQuota") {
		t.Error("missing ResourceQuota warning")
	}
	if !strings.Contains(out, "[MED]  Namespace ns1 has no LimitRange") {
		t.Error("missing LimitRange warning")
	}
	if !strings.Contains(out, "[MED]  Namespace ns1 default ServiceAccount is in use") {
		t.Error("missing default SA usage warning")
	}

	// RoleBinding messages
	if !strings.Contains(out, "[HIGH] Namespace ns1 default SA is bound to cluster-admin") {
		t.Error("missing HIGH role-binding message")
	}
	if !strings.Contains(out, "[MED]  Default SA in ns1 bound to role edit") {
		t.Error("missing MED role-binding message")
	}

	// Summary
	if !strings.Contains(out, "Total Checks Run        : 5") {
		t.Error("wrong total checks in summary")
	}
	if !strings.Contains(out, "High Severity Findings  : 1") {
		t.Error("wrong high count in summary")
	}
	if !strings.Contains(out, "Medium Severity Findings: 4") {
		t.Error("wrong medium count in summary")
	}
}
