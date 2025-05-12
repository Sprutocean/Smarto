# Ethereum Security Toolkit

A comprehensive toolkit for analyzing Ethereum smart contracts, detecting vulnerabilities, and understanding contract relationships.

## Features

- **Contract Information Retrieval**: Get basic information about any Ethereum contract including balance, token details, and more
- **Bytecode Analysis**: Disassemble contract bytecode to understand its low-level functionality
- **Reentrancy Vulnerability Detection**: Identify potential reentrancy vulnerabilities in smart contracts
- **Contract Relationship Analysis**: Detect proxy patterns, child contract creation, and implementation addresses
- **Function Signature Identification**: Map function selectors to their corresponding function signatures
- **Popular Contracts Library**: Analyze well-known Ethereum contracts with a single command

## Prerequisites

- Python 3.6+
- Required Python packages:
  - web3
  - requests

## Installation

1. Clone this repository or download the scripts
2. Install required packages:

```bash
pip install web3 requests
```

## Usage

The toolkit provides a unified command-line interface through the `ethereum-security-toolkit.py` script:

### Full Contract Analysis

```bash
python ethereum-security-toolkit.py analyze 0xYourContractAddress -n mainnet -o results.json
```

This performs a comprehensive analysis including:
- Contract information retrieval
- Bytecode disassembly
- Reentrancy vulnerability detection
- Contract relationship analysis

### Reentrancy Vulnerability Check

```bash
python ethereum-security-toolkit.py reentrancy 0xYourContractAddress -n mainnet
```

### Bytecode Analysis

```bash
python ethereum-security-toolkit.py bytecode 0xYourContractAddress -n mainnet
```

### Contract Relationship Analysis

```bash
python ethereum-security-toolkit.py relations 0xYourContractAddress -n mainnet
```

### Analyzing Popular Contracts

The toolkit includes a library of popular Ethereum contracts that can be analyzed with a simple command:

```bash
# List all available popular contracts
python ethereum-security-toolkit.py popular -l

# Analyze a specific popular contract (e.g., Uniswap V2 Router)
python ethereum-security-toolkit.py popular -n 1 -t analyze -o results.json
```

Available popular contracts include:
1. Uniswap V2 Router
2. USDC Token
3. DAI Stablecoin
4. Wrapped Ether (WETH)
5. Aave Lending Pool
6. Compound cETH
7. Uniswap V3 Factory
8. Uniswap V2 Factory
9. OpenSea Proxy
10. ENS Registry

## Individual Tools

The toolkit consists of several individual tools that can be used separately:

### 1. info-getter.py

Retrieves Ethereum contract information including token details, proxy detection, and bytecode.

### 2. bytecode.py

Disassembles EVM bytecode and identifies function signatures.

### 3. reentrancy-vulnerability-checker.py

Analyzes contract functions for potential reentrancy vulnerabilities.

### 4. child-parent.py

Analyzes contract relationships, detects proxy patterns, and identifies child/parent contracts.

## Configuration

By default, the toolkit connects to Ethereum Mainnet via Infura. You can modify the API keys in each script if needed, and specify different networks:

- mainnet (default)
- goerli
- sepolia

## Examples

### Analyze USDC Token Contract

```bash
python ethereum-security-toolkit.py analyze 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
```

### Check Uniswap V2 Router for Reentrancy

```bash
python ethereum-security-toolkit.py reentrancy 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D
```

### Use the Popular Contracts Feature

```bash
# List all popular contracts
python ethereum-security-toolkit.py popular -l

# Analyze Uniswap V2 Router
python ethereum-security-toolkit.py popular -n 1

# Check AAVE Lending Pool for reentrancy vulnerabilities
python ethereum-security-toolkit.py popular -n 5 -t reentrancy

# Analyze relationship patterns in OpenSea Proxy
python ethereum-security-toolkit.py popular -n 9 -t relations
```

## Limitations

- The reentrancy vulnerability checker operates on bytecode level and may produce false positives
- Function signature detection depends on known signatures and may not identify all functions
- The toolkit requires an internet connection to fetch data from the Ethereum blockchain

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 