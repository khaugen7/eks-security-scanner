package scanner

import (
	"context"
	"fmt"

	"github.com/khaugen7/eks-security-scanner/internal/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func RunNamespaceCheck(namespace string, client kubernetes.Interface) {
	utils.PrintScannerHeader("Namespace Scanner")
	var namespaces []string
	if namespace == "" {
		fmt.Print("\n[+] Scanning all namespaces for security configuration issues...\n")

		nsList, err := client.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("Failed to list namespaces: %v\n", err)
			return
		}

		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	} else {
		namespaces = []string{namespace}
			fmt.Printf("\n[+] Scanning namespace: %s for security configuration issues...\n", namespace)
	}

	for _, ns := range namespaces {
		var high, med, total int

		if !hasResourceQuota(ns, client) {
			fmt.Printf("[MED]  Namespace %s has no ResourceQuota: Pods may consume unbounded cluster resources\n", ns)
			med++
		}
		total++

		if !hasLimitRange(ns, client) {
			fmt.Printf("[MED]  Namespace %s has no LimitRange: Containers may run without CPU/memory limits\n", ns)
			med++
		}
		total++

		if defaultSAUsed(ns, client) {
			fmt.Printf("[MED]  Namespace %s default ServiceAccount is in use: recommend using dedicated SAs for workloads\n", ns)
			med++
		}
		total++

		roleFindings := checkDefaultSARoleBindings(ns, client)
		for _, f := range roleFindings {
			fmt.Println(f.Message)
			if f.Severity == "HIGH" {
				high++
			} else {
				med++
			}
		}
		total += len(roleFindings)

		fmt.Printf("\n[✓] Namespace Risk Summary\n")
		fmt.Printf("    Namespace Scanned       : %s\n", ns)
		fmt.Printf("    Total Checks Run        : %d\n", total)
		fmt.Printf("    High Severity Findings  : %d\n", high)
		fmt.Printf("    Medium Severity Findings: %d\n", med)
		fmt.Print("\n")
	}
}

func hasResourceQuota(namespace string, client kubernetes.Interface) bool {
	rqs, err := client.CoreV1().ResourceQuotas(namespace).List(context.TODO(), metav1.ListOptions{})
	return err == nil && len(rqs.Items) > 0
}

func hasLimitRange(namespace string, client kubernetes.Interface) bool {
	lrs, err := client.CoreV1().LimitRanges(namespace).List(context.TODO(), metav1.ListOptions{})
	return err == nil && len(lrs.Items) > 0
}

func defaultSAUsed(namespace string, client kubernetes.Interface) bool {
	sa, err := client.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), "default", metav1.GetOptions{})
	if err != nil {
		return false
	}
	return len(sa.Secrets) > 0 || len(sa.Annotations) > 0 || len(sa.ImagePullSecrets) > 0
}

type RiskFinding struct {
	Message  string
	Severity string
}

func checkDefaultSARoleBindings(namespace string, client kubernetes.Interface) []RiskFinding {
	var findings []RiskFinding

	rbs, err := client.RbacV1().RoleBindings(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return findings
	}

	for _, rb := range rbs.Items {
		for _, subject := range rb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Name == "default" {
				if rb.RoleRef.Kind == "ClusterRole" && rb.RoleRef.Name == "cluster-admin" {
					findings = append(findings, RiskFinding{
						Severity: "HIGH",
						Message:  fmt.Sprintf("[HIGH] Namespace %s default SA is bound to cluster-admin", namespace),
					})
				} else {
					findings = append(findings, RiskFinding{
						Severity: "MED",
						Message:  fmt.Sprintf("[MED]  Default SA in %s bound to role %s", namespace, rb.RoleRef.Name),
					})
				}
			}
		}
	}
	return findings
}
