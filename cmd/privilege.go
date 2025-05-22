/*
Copyright © 2025 Kyle Haugen kylehaugen.dev
*/
package cmd

import (
	"fmt"

	"github.com/khaugen7/eks-security-scanner/internal/scanner"
	"github.com/khaugen7/eks-security-scanner/pkg/kube"
	"github.com/spf13/cobra"
)

// privilegeCmd represents the privilege command
var privilegeCmd = &cobra.Command{
	Use:   "privilege",
	Short: "Scans pods for privileged permissions or root access.",
	Long: `Scans all Pods and highlights:
- privileged: true or hostPID/hostNetwork/hostPath
- Containers running as root
- Dangerous Linux capabilities`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running privileges scan...")
		namespace, _ := rootCmd.Flags().GetString("namespace")
		client := kube.GetClient()
		scanner.RunPrivilegeCheck(namespace, client)
	},
}

func init() {
	rootCmd.AddCommand(privilegeCmd)
}
