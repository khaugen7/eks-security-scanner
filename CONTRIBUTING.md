# Contributing to eks-security-scanner

First off, thank you for considering contributing to this project! Your input and ideas help improve the security tooling ecosystem for Kubernetes.

The following is a set of guidelines for contributing to eks-security-scanner. These are not hard rules, but suggestions to make collaboration smoother.

---

## Getting Started

1. Fork the repository

2. Clone your fork
        
    `git clone https://github.com/<your-username>/eks-security-scanner.git`

3. Install dependencies

    `go mod tidy`

4. Run tests
    
    `go test ./...`

## Contributing Workflow

- Use feature branches (`feature/<name>` or `fix/<name>`)

- Make sure your code is formatted with `go fmt`

- Add unit tests where applicable

- Run `go test ./...` and ensure all tests pass

- Submit a pull request to the `main` branch

- Provide a clear description of the change

- Include screenshots or example output where applicable

## Code Style

- Follow idiomatic Go practices

- Keep logic in `internal/` packages

- Keep CLI entry points in `cmd/`

- Avoid adding new dependencies unless necessary

## Testing

We use Go's built-in testing framework. Place tests in the same package, named with `_test.go`. For shared testing utilities, use `internal/testhelpers/`.

## Issues

Use GitHub Issues to report bugs, request features, or ask questions.

When filing an issue, include:

1. Reproduction steps

2. Expected vs actual behavior

3. Version of Kubernetes and eks-security-scanner

## Security Disclosure

If you discover a security vulnerability, please report it responsibly via the contact form at https://kylehaugen.dev/contact. We take security seriously and will respond as quickly as possible.

---

Thank you again for your contributions!