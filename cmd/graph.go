/*
Copyright © 2025 Kyle Haugen kylehaugen.dev
*/
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/khaugen7/eks-security-scanner/internal/kube"
	"github.com/khaugen7/eks-security-scanner/internal/scanner"
)

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Generate a threat graph of your EKS cluster in ASCII (default) or DOT format",
	Long: `Generate a threat graph of your EKS cluster by analyzing relationships between Pods, Services, Endpoints, ServiceAccounts, and IAM roles.

	This command models potential attack paths by mapping:
	- Pod → ServiceAccount → IAM Role (via IRSA)
	- Pod → Service (based on label selectors)
	- Service → Endpoint (pod IPs behind services)

	The resulting graph helps visualize the blast radius of a compromised Pod or identity.

	You can output the graph in either:
	- ASCII (default) for quick CLI inspection
	- DOT (Graphviz format) for advanced visualization or reporting

	Example usage:
	eks-scanner graph --cluster my-eks-cluster
	eks-scanner graph --cluster my-eks-cluster --format dot`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("format")
		namespace, _ := cmd.Flags().GetString("namespace")
		client := kube.GetClient()

		scanner.RunGraphCheck(outputFormat, namespace, client)
	},
}

func init() {
	rootCmd.AddCommand(graphCmd)
}
