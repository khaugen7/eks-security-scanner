package scanner

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/khaugen7/eks-security-scanner/internal/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func RunNamespaceCheck(namespace string, client kubernetes.Interface) {
	fmt.Print(utils.PrintScannerHeader("Namespace Scanner"))
	var namespaces []string
	if namespace == "" {
		log.Debug("No namespace provided.\n")
		log.Info("[+] Scanning all namespaces for security configuration issues...\n")

		nsList, err := client.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("Failed to list namespaces: %v\n", err)
			return
		}

		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	} else {
		namespaces = []string{namespace}
		log.Infof("[+] Scanning namespace: %s for security configuration issues...\n", namespace)
	}

	fmt.Println()

	for _, ns := range namespaces {
		log.Debugf("Evaluating namespace: %s\n", ns)
		var high, med, total int

		if !hasResourceQuota(ns, client) {
			log.Warnf("[MED]  Namespace %s has no ResourceQuota: Pods may consume unbounded cluster resources\n", ns)
			med++
		}
		total++

		if !hasLimitRange(ns, client) {
			log.Warnf("[MED]  Namespace %s has no LimitRange: Containers may run without CPU/memory limits\n", ns)
			med++
		}
		total++

		if defaultSAUsed(ns, client) {
			log.Warnf("[MED]  Namespace %s default ServiceAccount is in use: recommend using dedicated SAs for workloads\n", ns)
			med++
		}
		total++

		roleFindings := checkDefaultSARoleBindings(ns, client)
		for _, f := range roleFindings {
			log.Warn(f.Message)
			if f.Severity == "HIGH" {
				high++
			} else {
				med++
			}
		}
		total += len(roleFindings)

		fmt.Println()
		log.Infof("[✓] Namespace Risk Summary\n")
		log.Infof("    Namespace Scanned       : %s\n", ns)
		log.Infof("    Total Checks Run        : %d\n", total)
		log.Infof("    High Severity Findings  : %d\n", high)
		log.Infof("    Medium Severity Findings: %d\n", med)
		fmt.Println()
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
		log.Debugf("Checking subjects for RoleBinding: %s\n", rb.Name)
		for _, subject := range rb.Subjects {
			log.Debugf("Evaluating subject: %s\n", subject.Name)
			if subject.Kind == "ServiceAccount" && subject.Name == "default" {
				if rb.RoleRef.Kind == "ClusterRole" && rb.RoleRef.Name == "cluster-admin" {
					findings = append(findings, RiskFinding{
						Severity: "HIGH",
						Message:  fmt.Sprintf("[HIGH] Namespace %s default SA is bound to cluster-admin\n", namespace),
					})
				} else {
					findings = append(findings, RiskFinding{
						Severity: "MED",
						Message:  fmt.Sprintf("[MED]  Default SA in %s bound to role %s\n", namespace, rb.RoleRef.Name),
					})
				}
			}
		}
	}
	return findings
}
