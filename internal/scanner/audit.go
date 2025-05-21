package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	
	"k8s.io/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AWSAuthRole struct {
	RoleARN  string   `yaml:"rolearn"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups"`
}

type AWSAuthUser struct {
	UserARN  string   `yaml:"userarn"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups"`
}

func RunAuditCheck(clusterName string, client *kubernetes.Clientset) {
	roleARNs, err := GetIAMRolesFromEKSAccessEntries(clusterName)
	if err != nil {
		fmt.Printf("Failed to fetch EKS access entries: %v\n", err)
		return
	}
	CheckIAMPoliciesForRoles(roleARNs)
	CheckStaleRoles(roleARNs, 90)
	CheckClusterRoleBindings(client)
}

func CheckIAMPoliciesForRoles(roleARNs []string) {
    cfg, err := config.LoadDefaultConfig(context.TODO())
    if err != nil {
        fmt.Printf("unable to load AWS SDK config, %v", err)
		return
    }

    client := iam.NewFromConfig(cfg)

    for _, roleARN := range roleARNs {
        roleName := extractRoleName(roleARN)

        policies, err := client.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{
            RoleName: aws.String(roleName),
        })

        if err != nil {
            fmt.Printf("Error listing policies for %s: %v\n", roleName, err)
            continue
        }

        for _, policy := range policies.AttachedPolicies {
            version, err := getPolicyDocument(client, *policy.PolicyArn)
            if err != nil {
                fmt.Printf("Error getting policy %s: %v\n", *policy.PolicyArn, err)
                continue
            }

            if isOverlyPermissive(version) {
                fmt.Printf("[!] Dangerously permissive policy detected: role=%s policy=%s\n", roleName, *policy.PolicyName)
            }
        }
    }
}

func CheckStaleRoles(roleARNs []string, thresholdDays int) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Failed to load AWS config: %v\n", err)
		return
	}
	client := iam.NewFromConfig(cfg)

	cutoff := time.Now().AddDate(0, 0, -thresholdDays)

	fmt.Printf("\n[+] Checking for stale roles (unused in > %d days)...\n", thresholdDays)

	var total, stale, unknown int

	for _, arn := range roleARNs {
		roleName := extractRoleName(arn)
		total++

		output, err := client.GetRole(context.TODO(), &iam.GetRoleInput{
			RoleName: aws.String(roleName),
		})
		if err != nil {
			fmt.Printf("  [!] Failed to get role %s: %v\n", roleName, err)
			continue
		}

		lastUsed := output.Role.RoleLastUsed
		if lastUsed == nil || lastUsed.LastUsedDate == nil {
			fmt.Printf("  [?] Role %s has never been used or has no usage data.\n", roleName)
			unknown++
			continue
		}

		if lastUsed.LastUsedDate.Before(cutoff) {
			fmt.Printf("  [!] Role %s is stale. Last used: %s\n", roleName, lastUsed.LastUsedDate.Format("2006-01-02"))
			stale++
		} else {
			fmt.Printf("  [OK] Role %s was last used on %s\n", roleName, lastUsed.LastUsedDate.Format("2006-01-02"))
		}
	}

	fmt.Printf("\n[✓] Stale Role Scan Summary\n")
	fmt.Printf("    Total roles scanned: %d\n", total)
	fmt.Printf("    Stale roles found  : %d\n", stale)
	fmt.Printf("    Unknown/unused     : %d\n", unknown)
	fmt.Printf("    Active roles       : %d\n", total-stale-unknown)
}


func CheckClusterRoleBindings(client *kubernetes.Clientset) {
	crbs, err := client.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("Failed to fetch ClusterRoleBindings:", err)
		return
	}

	fmt.Println("\n[+] ClusterRoleBindings to cluster-admin or risky roles:")

	for _, crb := range crbs.Items {
		role := crb.RoleRef.Name
		if role == "cluster-admin" || strings.Contains(role, "admin") {
			fmt.Printf("- CRB: %s binds to role: %s\n", crb.Name, role)
			for _, subject := range crb.Subjects {
				fmt.Printf("  -> Kind: %s, Name: %s, Namespace: %s\n", subject.Kind, subject.Name, subject.Namespace)
			}
		}
	}
}

func GetIAMRolesFromEKSAccessEntries(clusterName string) ([]string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	client := eks.NewFromConfig(cfg)

	var roleARNs []string
	input := &eks.ListAccessEntriesInput{
		ClusterName: &clusterName,
	}

	paginator := eks.NewListAccessEntriesPaginator(client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("error paging access entries: %w", err)
		}

		for _, entry := range page.AccessEntries {
			// The entry is usually the full role ARN
			if strings.HasPrefix(entry, "arn:aws:iam::") {
				roleARNs = append(roleARNs, entry)
			}
		}
	}

	return roleARNs, nil
}

func extractRoleName(roleARN string) string {
	parts := strings.Split(roleARN, "/")
	return parts[len(parts)-1]
}

func getPolicyDocument(client *iam.Client, policyArn string) (string, error) {
	policy, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return "", fmt.Errorf("GetPolicy failed: %w", err)
	}

	versionID := policy.Policy.DefaultVersionId

	version, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: versionID,
	})
	if err != nil {
		return "", fmt.Errorf("GetPolicyVersion failed: %w", err)
	}

	doc, err := url.QueryUnescape(*version.PolicyVersion.Document)
	if err != nil {
		return "", fmt.Errorf("failed to decode policy document: %w", err)
	}

	return doc, nil
}

func isOverlyPermissive(policyJSON string) bool {
	var doc struct {
		Statement []struct {
			Effect   string      `json:"Effect"`
			Action   interface{} `json:"Action"`
			Resource interface{} `json:"Resource"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		fmt.Printf("Failed to parse IAM policy JSON: %v\n", err)
		return false
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		// Normalize to string slice
		actions := normalizeStringOrSlice(stmt.Action)
		resources := normalizeStringOrSlice(stmt.Resource)

		for _, action := range actions {
			if action == "*" || strings.HasSuffix(action, ":*") {
				return true
			}
		}
		for _, resource := range resources {
			if resource == "*" {
				return true
			}
		}
	}
	return false
}

func normalizeStringOrSlice(field interface{}) []string {
	switch v := field.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}
