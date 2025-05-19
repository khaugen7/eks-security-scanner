package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/khaugen7/eks-security-scanner/pkg/kube"
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


func RunAuditCheck() {
	client := kube.GetClient()
	cm, err := client.CoreV1().ConfigMaps("kube-system").Get(context.TODO(), "aws-auth", metav1.GetOptions{})
	if err != nil {
		fmt.Println("Error fetching aws-auth:", err)
		return
	}

	mapRoles := cm.Data["mapRoles"]
	mapUsers := cm.Data["mapUsers"]

	roles := ParseMapRoles(mapRoles)
	users := ParseMapUsers(mapUsers)

	PrintIAMBindings(roles, users)
	FindOverprivilegedIdentities(roles, users)
	CheckClusterRoleBindings()

	var roleARNs []string
	for _, r := range roles {
		roleARNs = append(roleARNs, r.RoleARN)
	}

	CheckIAMPoliciesForRoles(roleARNs)
}

func PrintIAMBindings(roles []AWSAuthRole, users []AWSAuthUser) {
	fmt.Println("\nIAM Role Bindings:")
	for _, r := range roles {
		fmt.Printf("- %s -> %s %v\n", r.RoleARN, r.Username, r.Groups)
	}
	fmt.Println("\nIAM User Bindings:")
	for _, u := range users {
		fmt.Printf("- %s -> %s %v\n", u.UserARN, u.Username, u.Groups)
	}
}

func FindOverprivilegedIdentities(roles []AWSAuthRole, users []AWSAuthUser) {
	fmt.Println("\n[!] Overprivileged Identities (system:masters):")
	for _, r := range roles {
		for _, g := range r.Groups {
			if g == "system:masters" {
				fmt.Printf("ROLE: %s (username: %s)\n", r.RoleARN, r.Username)
			}
		}
	}
	for _, u := range users {
		for _, g := range u.Groups {
			if g == "system:masters" {
				fmt.Printf("USER: %s (username: %s)\n", u.UserARN, u.Username)
			}
		}
	}
}

func CheckClusterRoleBindings() {
	client := kube.GetClient()

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

func CheckIAMPoliciesForRoles(roleARNs []string) {
    cfg, err := config.LoadDefaultConfig(context.TODO())
    if err != nil {
        log.Fatalf("unable to load AWS SDK config, %v", err)
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
                fmt.Printf("[!] Overly permissive policy detected on %s: %s\n", roleName, *policy.PolicyName)
            }
        }
    }
}

func ParseMapRoles(data string) []AWSAuthRole {
	var roles []AWSAuthRole
	if err := yaml.Unmarshal([]byte(data), &roles); err != nil {
		fmt.Println("Failed to parse mapRoles:", err)
	}
	return roles
}

func ParseMapUsers(data string) []AWSAuthUser {
	var users []AWSAuthUser
	if err := yaml.Unmarshal([]byte(data), &users); err != nil {
		fmt.Println("Failed to parse mapUsers:", err)
	}
	return users
}

func extractRoleName(roleARN string) string {
	parts := strings.Split(roleARN, "/")
	return parts[len(parts)-1]
}

func getPolicyDocument(client *iam.Client, policyArn string) (string, error) {
	// Step 1: Get policy to find the default version
	policy, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return "", fmt.Errorf("GetPolicy failed: %w", err)
	}

	versionID := policy.Policy.DefaultVersionId

	// Step 2: Get policy version
	version, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: versionID,
	})
	if err != nil {
		return "", fmt.Errorf("GetPolicyVersion failed: %w", err)
	}

	// Step 3: Decode URL-encoded policy doc
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
