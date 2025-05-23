# eks-security-scanner

[![License](https://img.shields.io/github/license/khaugen7/eks-security-scanner)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/khaugen7/eks-security-scanner)](https://goreportcard.com/report/github.com/khaugen7/eks-security-scanner)
[![GitHub release](https://img.shields.io/github/v/release/khaugen7/eks-security-scanner)](https://github.com/khaugen7/eks-security-scanner/releases)


A CLI tool to scan AWS EKS clusters for misconfigurations, over-permissive access, and common Kubernetes security risks. Built in Go for speed and simplicity.

---

## Features

- Threat modeling with service-account access graphs
- Privileged pod detection
- RBAC and IAM access audits
- Namespace-level scope filtering
- Output as ASCII or DOT format
- Extensible CLI built with Cobra

---

## Installation

### Prebuilt Binaries

Download the latest release from [GitHub Releases](https://github.com/khaugen7/eks-security-scanner/releases) and place the binary in your `$PATH`.

Or install using the provided script:

#### Linux/macOS

`curl -fsSL https://raw.githubusercontent.com/khaugen7/eks-security-scanner/main/scripts/install.sh | bash
`

#### Windows (PowerShell)

`irm https://raw.githubusercontent.com/khaugen7/eks-security-scanner/main/scripts/install.ps1 | iex
`

### From Source (Requires Go)

git clone https://github.com/khaugen7/eks-security-scanner.git

`cd eks-security-scanner`

`go build -o eks-scanner main.go`

---

## Authentication Requirements

To use `eks-scanner`, you must have:

- **Kubernetes credentials** configured via `~/.kube/config` or the `KUBECONFIG` environment variable with access to your EKS cluster.
- **AWS credentials** configured via environment variables, a named profile, or the AWS CLI (`~/.aws/credentials`) with appropriate access to your AWS account.

This tool performs **read-only scanning** of your EKS environment. It does **not make any modifications** to your Kubernetes cluster or AWS resources.

Minimum required AWS IAM permissions:

- `eks:ListAccessEntries`
- `eks:DescribeAccessEntry`
- `eks:DescribeCluster`
- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`

Your Kubernetes user or IAM role must have **read access** to common cluster resources, including:

- Pods
- Namespaces
- Services
- Endpoints
- RoleBindings
- ServiceAccounts
- ConfigMaps
- ResourceQuotas
- LimitRanges

Ensure your identity has sufficient permissions in both AWS and Kubernetes to retrieve this data.

---

## Usage

### Help Menu

`eks-scanner --help`

```
Scan your EKS cluster for common security misconfigurations

Usage:
  eks-scanner [flags]
  eks-scanner [command]

Available Commands:
  audit       Scans EKS access entries and IAM permissions.
  completion  Generate the autocompletion script for the specified shell
  graph       Generate a threat graph of your EKS cluster in ASCII (default) or DOT format
  help        Help about any command
  namespace   Scan Kubernetes namespace(s) for security misconfigurations and over-permissive defaults
  privilege   Scans pods for privileged permissions or root access.

Flags:
  -a, --all                Run all checks
  -c, --cluster string     Name of the EKS cluster to scan (required)
  -f, --format string      Output format: ascii or dot (default "ascii")
  -h, --help               help for eks-scanner
  -n, --namespace string   Name of the namespace scan

Use "eks-scanner [command] --help" for more information about a command.
```

### Examples

`eks-scanner graph --cluster mycluster`

`eks-scanner audit -c mycluster`

`eks-scanner privilege -c mycluster --namespace mynamespace`

`eks-scanner --all -c mycluster -n namespace`

---

## Sample Output

<insert ASCII graph screenshot or sample scan output here>

---

## Documentation

- [Threat Modeling Guide](docs/threat-modeling.md)
- [Scan Types](docs/scan-types.md)
- [Interpreting Results](docs/interpreting-results.md)
- [Contribution Guide](CONTRIBUTING.md)

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

## Security

If you discover a vulnerability, please report it via the contact form at [https://kylehaugen.dev/contact](https://kylehaugen.dev/contact).

---

## Support

If you find eks-security-scanner helpful, consider [buying me a coffee](https://www.buymeacoffee.com/kylehaugen) to support continued development and maintenance. ☕️


## Acknowledgements

Built with:
- [Cobra CLI](https://github.com/spf13/cobra)
- [k8s.io/client-go](https://github.com/kubernetes/client-go)
