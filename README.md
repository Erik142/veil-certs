# veil-certs: Automated Nebula Certificate & IP Management

![Nebula Logo](https://raw.githubusercontent.com/slackhq/nebula/master/docs/nebula_logo.png)

`veil-certs` is a comprehensive solution designed to streamline the management of certificates and IP addresses for your [Nebula](https://github.com/slackhq/nebula) overlay networks. It provides a robust server-side component for automated certificate generation and IP lease management, complemented by a client for seamless interaction.

Say goodbye to manual certificate signing and IP allocation headaches. `veil-certs` empowers you to build and maintain dynamic, secure, and scalable Nebula networks with ease.

## ✨ Features

*   **Automated Certificate Generation:** On-demand generation of Nebula host certificates, signed by your designated Certificate Authority (CA).
*   **IP Address Management (IPAM):** Centralized management of IP address leases for Nebula hosts, preventing conflicts and simplifying network scaling.
*   **Secure Key Handling:** Integrates with configurable key passphrase providers to protect your CA private keys.
*   **gRPC API:** A well-defined gRPC interface (`nebulacert.proto`) for programmatic interaction with the certificate and IP management services.
*   **Configurable CA Store:** Supports different backends for storing CA certificates and keys (e.g., file-based).
*   **Client Application:** A command-line client to request certificates and manage IP leases from the `veil-certs` server.

## 🚀 Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have the following installed:

*   [Go](https://golang.org/doc/install) (version 1.18 or higher recommended)
*   [Nebula](https://github.com/slackhq/nebula#installation) (for testing your generated certificates)

### Installation & Building

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Erik142/veil-certs.git
    cd veil-certs
    ```

2.  **Build the server and client binaries:**

    ```bash
    go build -o bin/nebulacert-server ./cmd/nebulacert-server
    go build -o bin/nebulacert-client ./cmd/client
    ```

### Configuration

The `nebulacert-server` relies on a `config.yaml` file for its operational parameters, including CA details, IPAM ranges, and server listening addresses. An example configuration is located in `configs/config.yaml`.

Before running the server, you'll need to:

1.  **Generate your Nebula CA:** Follow the [official Nebula documentation](https://docs.nebula.dev/how-to/create-ca) to create your CA certificate and key.
2.  **Update `configs/config.yaml`:** Adjust the paths to your CA certificate and key, define your IPAM ranges, and configure other server settings as needed.

    ```yaml
    # Example config.yaml
    server:
      listen_address: "0.0.0.0:8080"
    ca_store:
      type: "file"
      file:
        ca_cert_path: "/path/to/your/ca.crt"
        ca_key_path: "/path/to/your/ca.key"
    ip_manager:
      lease_duration: "24h"
      subnets:
        - "10.0.0.0/24"
    key_provider:
      type: "plaintext"
      plaintext:
        passphrase: "your-ca-key-passphrase" # Use a secure method for production!
    ```

### Running the Server

Once configured, you can start the `nebulacert-server`:

```bash
./bin/nebulacert-server --config configs/config.yaml
```

### Running the Client

The `nebulacert-client` can be used to interact with the running server. Refer to its help output for available commands:

```bash
./bin/nebulacert-client --help
```

## 📂 Project Structure

*   `cmd/`: Contains the main entry points for the `nebulacert-server` and `client` applications.
*   `configs/`: Stores example and default configuration files.
*   `pkg/`: Houses the core logic and reusable packages:
    *   `castore/`: Interfaces and implementations for managing the Certificate Authority store.
    *   `certgen/`: Logic for generating Nebula host certificates.
    *   `ipmanager/`: Handles IP address leasing and management.
    *   `keyprovider/`: Provides mechanisms for securely accessing CA key passphrases.
    *   `proto/`: Defines the gRPC service (`nebulacert.proto`) for inter-service communication.
    *   `server/`: Contains the main server implementation and gRPC service handlers.

## 🤝 Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.
