package scanner

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/khaugen7/eks-security-scanner/pkg/kube"
)

func RunAuditCheck() {
	clientset := kube.GetClient() // wrapped in internal/kubeclient.go
	cm, err := clientset.CoreV1().ConfigMaps("kube-system").Get(context.TODO(), "aws-auth", metav1.GetOptions{})
	if err != nil {
		fmt.Println("Error fetching aws-auth:", err)
		return
	}

	data := cm.Data["mapRoles"]
	fmt.Println("IAM Role Bindings in aws-auth:")
	fmt.Println(data)
	// TODO: parse yaml, flag wildcard admin roles
}
