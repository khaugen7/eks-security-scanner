package scanner

import (
	"context"
	"fmt"

	"github.com/khaugen7/eks-security-scanner/internal/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func RunPrivilegeCheck(namespace string, client kubernetes.Interface) {
	utils.PrintScannerHeader("Privileges Scanner")

	pods, err := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Failed to list pods: %v\n", err)
		return
	}

	var totalPods, highFindings, medFindings int

	fmt.Printf("\n[+] Scanning Pods in namespace: %s for privilege issues...\n", namespace)

	for _, pod := range pods.Items {
		totalPods++
		podID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		if pod.Spec.SecurityContext != nil {
			if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
				fmt.Printf("[HIGH] Pod %s is running as root user\n", podID)
				highFindings++
			}
			if pod.Spec.SecurityContext.RunAsNonRoot != nil && !*pod.Spec.SecurityContext.RunAsNonRoot {
				fmt.Printf("[MED] Pod %s is not enforcing non-root execution\n", podID)
				medFindings++
			}
		}

		for _, c := range pod.Spec.Containers {
			containerID := fmt.Sprintf("%s (%s)", podID, c.Name)
			sc := c.SecurityContext

			if sc != nil {
				if sc.Privileged != nil && *sc.Privileged {
					fmt.Printf("[HIGH] Container %s is running as privileged: grants full access to host devices and kernel\n", containerID)
					highFindings++
				}
				if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
					fmt.Printf("[HIGH] Container %s is running as root\n", containerID)
					highFindings++
				}
				if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
					fmt.Printf("[MED] Container %s allows privilege escalation: users inside container can gain more privileges (e.g. sudo)\n", containerID)
					medFindings++
				}
				if sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
					fmt.Printf("[MED] Container %s adds Linux capabilities %v: expands kernel-level access beyond defaults\n", containerID, sc.Capabilities.Add)
					medFindings++
				}
			}
		}

		if pod.Spec.HostNetwork {
			fmt.Printf("[HIGH] Pod %s uses hostNetwork: shares network stack with host, bypasses network isolation\n", podID)
			highFindings++
		}
		if pod.Spec.HostPID {
			fmt.Printf("[HIGH] Pod %s uses hostPID: shares process space with host, can view/kill host processes\n", podID)
			highFindings++
		}
		if pod.Spec.HostIPC {
			fmt.Printf("[MED] Pod %s uses hostIPC: shares inter-process comm layer with host, can interfere with other pods\n", podID)
			medFindings++
		}

		for _, v := range pod.Spec.Volumes {
			if v.HostPath != nil {
				fmt.Printf("[HIGH] Pod %s mounts hostPath %s: exposes host filesystem to container\n", podID, v.HostPath.Path)
				highFindings++
			}
		}
	}

	fmt.Printf("\n[✓] Privilege Check Summary\n")
	fmt.Printf("    Namespace Scanned       : %s\n", namespace)
	fmt.Printf("    Total Pods Scanned      : %d\n", totalPods)
	fmt.Printf("    High Severity Findings  : %d\n", highFindings)
	fmt.Printf("    Medium Severity Findings: %d\n", medFindings)

}
