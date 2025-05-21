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
	Short: "Scans EKS access entries and IAM permissions.",
	Long: `Scans EKS access entries and IAM permissions.
Reports:
- All roles/users mapped to cluster-admin
- Unused or stale IAM roles (last used > X days)
- Dangerously permissive IAM policies`,
	Run: func(cmd *cobra.Command, args []string) {
	clusterName, err := cmd.Flags().GetString("cluster")
	if err != nil {
		fmt.Println("Failed to read --cluster flag:", err)
		return
	}
	if clusterName == "" {
		fmt.Println("Missing --cluster flag")
		return
	}

	scanner.RunAuditCheck(clusterName)
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
