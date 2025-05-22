/*
Copyright © 2025 Kyle Haugen kylehaugen.dev
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/khaugen7/eks-security-scanner/pkg/kube"
	"github.com/khaugen7/eks-security-scanner/internal/scanner"
	"github.com/spf13/cobra"
)

var allChecks bool
var clusterName string
var outputFormat string
var namespace string

func init() {
	rootCmd.PersistentFlags().BoolVarP(&allChecks, "all", "a", false, "Run all checks")
	rootCmd.PersistentFlags().StringVarP(&clusterName, "cluster", "c", "", "Name of the EKS cluster to scan (required)")
	rootCmd.MarkPersistentFlagRequired("cluster")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Name of the namespace scan")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "ascii", "Output format: ascii or dot")
}

var rootCmd = &cobra.Command{
	Use:   "eks-scanner",
	Short: "Scan your EKS cluster for common security misconfigurations",
	Run: func(cmd *cobra.Command, args []string) {
		if allChecks {
			client := kube.GetClient()
			fmt.Println("Running all checks...")
			// Run all scanners
			scanner.RunAuditCheck(clusterName, client)
			scanner.RunPrivilegeCheck(namespace, client)
			// scanner.RunNamespaceCheck()
			scanner.RunGraphCheck(outputFormat, namespace, client)
		} else {
			_ = cmd.Help()
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
