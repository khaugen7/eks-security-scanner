package scanner

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

    "github.com/khaugen7/eks-security-scanner/internal/testhelpers"
)

func TestRunPrivilegeCheck_AllFindings(t *testing.T) {
    // Build a fake clientset with one Pod that triggers every check
    zero := int64(0)
    fls := false
    tru := true

    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "pod1",
            Namespace: "ns1",
        },
        Spec: corev1.PodSpec{
            SecurityContext: &corev1.PodSecurityContext{
                RunAsUser:    &zero,
                RunAsNonRoot: &fls,
            },
            HostNetwork: true,
            HostPID:     true,
            HostIPC:     true,
            Volumes: []corev1.Volume{
                {Name: "v", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/host-path"}}},
            },
            Containers: []corev1.Container{{
                Name:  "ctr1",
                Image: "img",
                SecurityContext: &corev1.SecurityContext{
                    Privileged:               &tru,
                    RunAsUser:                &zero,
                    AllowPrivilegeEscalation: &tru,
                    Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
                },
            }},
        },
    }

    var client kubernetes.Interface = fake.NewSimpleClientset(pod)

    out := testhelpers.CaptureOutput(func() {
        RunPrivilegeCheck("ns1", client)
    })

    if !strings.Contains(out, "[HIGH] Pod ns1/pod1 is running as root user") {
        t.Error("missing root-user HIGH for pod")
    }
    if !strings.Contains(out, "[MED] Pod ns1/pod1 is not enforcing non-root execution") {
        t.Error("missing non-root MED for pod")
    }
    if !strings.Contains(out, "[HIGH] Pod ns1/pod1 uses hostNetwork") {
        t.Error("missing hostNetwork HIGH")
    }
    if !strings.Contains(out, "[HIGH] Pod ns1/pod1 uses hostPID") {
        t.Error("missing hostPID HIGH")
    }
    if !strings.Contains(out, "[MED] Pod ns1/pod1 uses hostIPC") {
        t.Error("missing hostIPC MED")
    }
    if !strings.Contains(out, "[HIGH] Pod ns1/pod1 mounts hostPath /host-path") {
        t.Error("missing hostPath HIGH")
    }

    if !strings.Contains(out, "[HIGH] Container ns1/pod1 (ctr1) is running as privileged") {
        t.Error("missing privileged HIGH for container")
    }
    if !strings.Contains(out, "[HIGH] Container ns1/pod1 (ctr1) is running as root") {
        t.Error("missing root-user HIGH for container")
    }
    if !strings.Contains(out, "[MED] Container ns1/pod1 (ctr1) allows privilege escalation") {
        t.Error("missing privilege-escalation MED")
    }
    if !strings.Contains(out, "[MED] Container ns1/pod1 (ctr1) adds Linux capabilities [NET_ADMIN]") {
        t.Error("missing capabilities MED")
    }

    if !strings.Contains(out, "Total Pods Scanned      : 1") {
        t.Error("summary: wrong total pods")
    }
    if !strings.Contains(out, "High Severity Findings  : 6") {
        t.Errorf("summary: expected 6 highs, got:\n%s", out)
    }
    if !strings.Contains(out, "Medium Severity Findings: 4") {
        t.Errorf("summary: expected 4 meds, got:\n%s", out)
    }
}
