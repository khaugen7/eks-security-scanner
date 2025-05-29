/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/khaugen7/eks-security-scanner/internal/kube"
	"github.com/khaugen7/eks-security-scanner/internal/scanner"
)

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
		client := kube.GetClient()

		if err != nil {
			log.Errorf("Failed to read --cluster flag: %s\n", err)
			return
		}
		if clusterName == "" {
			log.Error("Missing --cluster flag\n")
			return
		}
		scanner.RunAuditCheck(clusterName, client)
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
