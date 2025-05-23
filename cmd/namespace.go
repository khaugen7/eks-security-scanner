/*
Copyright © 2025 Kyle Haugen kylehaugen.dev
*/
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/khaugen7/eks-security-scanner/internal/kube"
	"github.com/khaugen7/eks-security-scanner/internal/scanner"
)

var namespaceCmd = &cobra.Command{
	Use:   "namespace",
	Short: "Scan Kubernetes namespace(s) for security misconfigurations and over-permissive defaults",
	Long: `Scan Kubernetes namespace(s) for security misconfigurations and over-permissive defaults.

This check identifies common namespace-level risks including:
  - Missing ResourceQuotas: Pods can consume unlimited CPU/memory
  - Missing LimitRanges: Containers may run without resource limits
  - Overuse of the default ServiceAccount: increases blast radius
  - Dangerous RoleBindings: default SA bound to cluster-admin or other powerful roles

These issues often go unnoticed in development clusters or shared environments and can lead to privilege escalation, denial of service, or full cluster compromise if left unchecked.

Example usage:
  eks-scanner namespace --cluster my-eks-cluster --namespace dev`,

	Run: func(cmd *cobra.Command, args []string) {
		namespace, _ := rootCmd.Flags().GetString("namespace")
		client := kube.GetClient()
		scanner.RunNamespaceCheck(namespace, client)
	},
}

func init() {
	rootCmd.AddCommand(namespaceCmd)
}
