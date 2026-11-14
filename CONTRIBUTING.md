# Contributing to safeMCA (MCP-Guard)

First off, thank you for considering contributing to **safeMCA**! We welcome contributions from developers, security researchers, and AI builders.

---

## 🛠️ Development Setup

### Prerequisites
* Rust 1.75+ (`rustup install stable`)
* Git

### Building Locally

```bash
git clone https://github.com/hamravichauhan/safeMCA.git
cd safeMCA

# Build in debug mode
cargo build

# Run the security self-test
cargo run -- test
```

### Running Tests

```bash
cargo test
cargo clippy -- -D warnings
```

---

## 🛡️ Security Vulnerability Reporting

If you discover a security vulnerability or bypass in the policy engine, please **DO NOT open a public GitHub issue**. Instead, please report it privately to the maintainers at `ravi486chauhan@gmail.com` with reproducible steps.

---

## 📜 Pull Request Guidelines

1. Fork the repo and create your branch from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Ensure your changes compile without warnings:
   ```bash
   cargo check
   cargo clippy
   ```
3. Run the policy self-test:
   ```bash
   cargo run -- test
   ```
4. Open a Pull Request with a clear summary of your changes.

---

## 📄 License
By contributing to safeMCA, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
