package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type GraphEdge struct {
	From string
	To   string
	Label string // optional
}

func RunGraphCheck(outputFormat string, client *kubernetes.Clientset) {
	pods, _ := client.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{})
	services, _ := client.CoreV1().Services("").List(context.TODO(), v1.ListOptions{})
	endpoints, _ := client.CoreV1().Endpoints("").List(context.TODO(), v1.ListOptions{})

	var edges []GraphEdge

	// Pod → SA → IAM Role
	for _, pod := range pods.Items {
		podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)

		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		saID := fmt.Sprintf("sa/%s/%s", pod.Namespace, saName)
		edges = append(edges, GraphEdge{From: podID, To: saID, Label: "uses"})

		// Check for IRSA annotation
		sa, err := client.CoreV1().ServiceAccounts(pod.Namespace).Get(context.TODO(), saName, v1.GetOptions{})
		if err == nil {
			iamArn := sa.Annotations["eks.amazonaws.com/role-arn"]
			if iamArn != "" {
				roleID := fmt.Sprintf("iam-role/%s", strings.Split(iamArn, "/")[1])
				edges = append(edges, GraphEdge{From: saID, To: roleID, Label: "assumes"})
			}
		}
	}

	// Pod → Service
	for _, svc := range services.Items {
		svcID := fmt.Sprintf("svc/%s/%s", svc.Namespace, svc.Name)

		for _, pod := range pods.Items {
			if pod.Namespace != svc.Namespace {
				continue
			}
			if selectorMatches(svc.Spec.Selector, pod.Labels) {
				podID := fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name)
				edges = append(edges, GraphEdge{From: podID, To: svcID, Label: "matches"})
			}
		}
	}

	// Service → Endpoints
	for _, ep := range endpoints.Items {
		svcID := fmt.Sprintf("svc/%s/%s", ep.Namespace, ep.Name)
		for _, subset := range ep.Subsets {
			for _, addr := range subset.Addresses {
				epID := fmt.Sprintf("ep/%s/%s", ep.Namespace, addr.IP)
				edges = append(edges, GraphEdge{From: svcID, To: epID, Label: "routes-to"})
			}
		}
	}

	if strings.ToLower(outputFormat) == "dot" {
		PrintDOTGraph(edges)
	} else {
		PrintASCIIGraph(edges)
	}}

func selectorMatches(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func PrintDOTGraph(edges []GraphEdge) {
	fmt.Println("[i] Copy the following DOT graph to https://edotor.net to visualize:\n")

	fmt.Println("digraph eks_threat_graph {")
	fmt.Println("  rankdir=LR;")

	for _, edge := range edges {
		fmt.Printf("  \"%s\" -> \"%s\" [label=\"%s\"];\n", edge.From, edge.To, edge.Label)
	}
	fmt.Println("}")
}

func PrintASCIIGraph(edges []GraphEdge) {
	graph := make(map[string][]GraphEdge)

	for _, edge := range edges {
		graph[edge.From] = append(graph[edge.From], edge)
	}

	sources := make([]string, 0, len(graph))
	for src := range graph {
		sources = append(sources, src)
	}
	sort.Strings(sources)

	fmt.Println("\nThreat Graph (ASCII Format):\n")

	for _, src := range sources {
		fmt.Printf("%s\n", formatNode(src))

		for _, edge := range graph[src] {
			fmt.Printf("  └─[%s]→ %s\n", edge.Label, formatNode(edge.To))
		}
	}
}

func formatNode(id string) string {
	switch {
	case strings.HasPrefix(id, "pod/"):
		return fmt.Sprintf("[POD] %s", strings.TrimPrefix(id, "pod/"))
	case strings.HasPrefix(id, "svc/"):
		return fmt.Sprintf("[SVC] %s", strings.TrimPrefix(id, "svc/"))
	case strings.HasPrefix(id, "ep/"):
		return fmt.Sprintf("[EP]  %s", strings.TrimPrefix(id, "ep/"))
	case strings.HasPrefix(id, "sa/"):
		return fmt.Sprintf("[SA]  %s", strings.TrimPrefix(id, "sa/"))
	case strings.HasPrefix(id, "iam-role/"):
		return fmt.Sprintf("[IAM] %s", strings.TrimPrefix(id, "iam-role/"))
	default:
		return id
	}
}
