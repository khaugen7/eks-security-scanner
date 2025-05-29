package scanner

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/khaugen7/eks-security-scanner/internal/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func RunPrivilegeCheck(namespace string, client kubernetes.Interface) {
	fmt.Print(utils.PrintScannerHeader("Privileges Scanner"))

	pods, err := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("Failed to list pods: %v\n", err)
		return
	}

	var totalPods, highFindings, medFindings int

	log.Infof("[+] Scanning Pods in namespace: %s for privilege issues...\n", namespace)

	for _, pod := range pods.Items {
		totalPods++
		podID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
		log.Debugf("Checking pod: %s\n", podID)

		if pod.Spec.SecurityContext != nil {
			if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
				log.Warnf("[HIGH] Pod %s is running as root user\n", podID)
				highFindings++
			}
			if pod.Spec.SecurityContext.RunAsNonRoot != nil && !*pod.Spec.SecurityContext.RunAsNonRoot {
				log.Warnf("[MED] Pod %s is not enforcing non-root execution\n", podID)
				medFindings++
			}
		}

		for _, c := range pod.Spec.Containers {
			containerID := fmt.Sprintf("%s (%s)", podID, c.Name)
			log.Debugf("Checking container: %s\n", containerID)
			sc := c.SecurityContext

			if sc != nil {
				if sc.Privileged != nil && *sc.Privileged {
					log.Warnf("[HIGH] Container %s is running as privileged: grants full access to host devices and kernel\n", containerID)
					highFindings++
				}
				if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
					log.Warnf("[HIGH] Container %s is running as root\n", containerID)
					highFindings++
				}
				if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
					log.Warnf("[MED] Container %s allows privilege escalation: users inside container can gain more privileges (e.g. sudo)\n", containerID)
					medFindings++
				}
				if sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
					log.Warnf("[MED] Container %s adds Linux capabilities %v: expands kernel-level access beyond defaults\n", containerID, sc.Capabilities.Add)
					medFindings++
				}
			}
		}

		if pod.Spec.HostNetwork {
			log.Warnf("[HIGH] Pod %s uses hostNetwork: shares network stack with host, bypasses network isolation\n", podID)
			highFindings++
		}
		if pod.Spec.HostPID {
			log.Warnf("[HIGH] Pod %s uses hostPID: shares process space with host, can view/kill host processes\n", podID)
			highFindings++
		}
		if pod.Spec.HostIPC {
			log.Warnf("[MED] Pod %s uses hostIPC: shares inter-process comm layer with host, can interfere with other pods\n", podID)
			medFindings++
		}

		for _, v := range pod.Spec.Volumes {
			if v.HostPath != nil {
				log.Warnf("[HIGH] Pod %s mounts hostPath %s: exposes host filesystem to container\n", podID, v.HostPath.Path)
				highFindings++
			}
		}
	}

	fmt.Println()
	log.Infof("[✓] Privilege Check Summary\n")
	log.Infof("    Namespace Scanned       : %s\n", namespace)
	log.Infof("    Total Pods Scanned      : %d\n", totalPods)
	log.Infof("    High Severity Findings  : %d\n", highFindings)
	log.Infof("    Medium Severity Findings: %d\n", medFindings)
	fmt.Println()
}
