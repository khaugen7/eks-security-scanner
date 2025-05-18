/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/khaugen7/eks-security-scanner/internal/scanner"
)

// auditCmd represents the audit command
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Scans the aws-auth ConfigMap and IAM bindings.",
	Long: `Scans the aws-auth ConfigMap and IAM bindings.
Reports:
- All IAM roles/users mapped to cluster-admin
- Unused or stale IAM roles (last used > X days)
- Cross-account access risks
- Pods with node-wide IAM via EC2 metadata`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running audit on aws-auth...")
		scanner.RunAuditCheck()
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// auditCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// auditCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
