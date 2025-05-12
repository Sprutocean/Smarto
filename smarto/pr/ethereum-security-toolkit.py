#!/usr/bin/env python3
"""
Ethereum Security Toolkit - Orchestrator Script
This script combines functionality from all the individual tools into a unified interface
for analyzing Ethereum smart contracts for security vulnerabilities and properties.
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Any, Optional
import importlib.util

# Define colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Popular Ethereum contracts for quick analysis
POPULAR_CONTRACTS = {
    "1": {
        "name": "Uniswap V2 Router",
        "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        "description": "The main router contract for Uniswap V2, handling swaps and liquidity operations"
    },
    "2": {
        "name": "USDC Token",
        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "description": "USD Coin stablecoin by Circle"
    },
    "3": {
        "name": "DAI Stablecoin",
        "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "description": "The DAI stablecoin by MakerDAO"
    },
    "4": {
        "name": "Wrapped Ether (WETH)",
        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "description": "ERC20 wrapped version of Ether"
    },
    "5": {
        "name": "Aave Lending Pool",
        "address": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
        "description": "Main contract for Aave lending protocol"
    },
    "6": {
        "name": "Compound cETH",
        "address": "0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5",
        "description": "Compound's cETH token for lending ETH"
    },
    "7": {
        "name": "Uniswap V3 Factory",
        "address": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "description": "Factory contract for Uniswap V3 pools"
    },
    "8": {
        "name": "Uniswap V2 Factory",
        "address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "description": "Factory contract for Uniswap V2 pairs"
    },
    "9": {
        "name": "OpenSea Proxy",
        "address": "0x00000000006c3852cbEf3e08E8dF289169EdE581",
        "description": "OpenSea NFT marketplace proxy contract"
    },
    "10": {
        "name": "ENS Registry",
        "address": "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
        "description": "Ethereum Name Service registry"
    }
}

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}==== {text} ===={Colors.ENDC}")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.ENDC}")

def print_warning(text):
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")

# Import module from file path
def import_from_file(module_name: str, file_path: str) -> Any:
    """Import a module from file path, handling hyphenated filenames."""
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if not spec or not spec.loader:
            raise ImportError(f"Could not load spec for {file_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print_error(f"Error importing {file_path}: {str(e)}")
        sys.exit(1)

# Check for required files
required_files = ["info-getter.py", "bytecode.py", "reentrancy-vulnerability-checker.py", "child-parent.py"]
missing_files = [f for f in required_files if not os.path.exists(f)]

if missing_files:
    print_error(f"Missing required files: {', '.join(missing_files)}")
    print("Please make sure all required script files are in the same directory.")
    sys.exit(1)

# Import all modules
print("Importing modules...")
info_getter = import_from_file("info_getter", "info-getter.py")
bytecode_analyzer = import_from_file("bytecode_analyzer", "bytecode.py")
reentrancy_checker = import_from_file("reentrancy_checker", "reentrancy-vulnerability-checker.py")
contract_relations = import_from_file("contract_relations", "child-parent.py")

def display_popular_contracts():
    """Display list of popular Ethereum contracts for analysis."""
    print_header("Popular Ethereum Contracts")
    for key, contract in POPULAR_CONTRACTS.items():
        print(f"{Colors.BOLD}{key}. {contract['name']}{Colors.ENDC}")
        print(f"   Address: {contract['address']}")
        print(f"   {contract['description']}")
        print()

def analyze_popular_contract(index: str, analysis_type: str = 'analyze', network: str = 'mainnet', output_file: Optional[str] = None):
    """Run analysis on a popular contract by its list index."""
    if index not in POPULAR_CONTRACTS:
        print_error(f"Invalid selection. Please choose a number between 1 and {len(POPULAR_CONTRACTS)}")
        return
    
    contract = POPULAR_CONTRACTS[index]
    address = contract['address']
    
    print_header(f"Selected: {contract['name']} ({address})")
    
    if analysis_type == 'analyze':
        run_full_analysis(address, network, output_file)
    elif analysis_type == 'reentrancy':
        print("Running reentrancy vulnerability check...")
        run_full_analysis(address, network)
    elif analysis_type == 'bytecode':
        analyze_bytecode(address, network)
    elif analysis_type == 'relations':
        analyze_relations(address, network)
    else:
        print_error(f"Invalid analysis type: {analysis_type}")

def check_reentrancy(instructions, function_sigs, contract_info):
    """
    Check for potential reentrancy vulnerabilities in a contract.
    
    Args:
        instructions: List of disassembled instructions
        function_sigs: Dict of function signatures
        contract_info: Contract information
        
    Returns:
        List of potential reentrancy findings
    """
    try:
        # Prepare functions for reentrancy check
        functions = []
        for sig, name in function_sigs.items():
            # Extract function name without parameters
            func_name = name.split('(')[0] if '(' in name else name
            
            # Create placeholder Operation objects for specific opcodes we see in the bytecode
            operations = []
            for instr in instructions:
                if 'CALL' in instr:
                    operations.append(reentrancy_checker.Operation(name='CALL'))
                elif 'SSTORE' in instr:
                    operations.append(reentrancy_checker.Operation(name='SSTORE'))
                elif 'SLOAD' in instr:
                    operations.append(reentrancy_checker.Operation(name='SLOAD'))
                
            # Create a Function object with the operations
            func = reentrancy_checker.Function(
                name=func_name,
                visibility='external' if sig in [s[:8] for s in contract_info.get('function_selectors', [])] else 'internal',
                operations=operations,
                modifiers=[]  # We don't have modifier info from bytecode alone
            )
            functions.append(func)
        
        # Run the reentrancy check
        findings = reentrancy_checker.find_potential_reentrancy_vulnerabilities(functions)
        return findings
    except Exception as e:
        print_error(f"Error checking for reentrancy: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

def run_full_analysis(address: str, network: str = 'mainnet', output_file: Optional[str] = None, skip_reentrancy: bool = False) -> Dict[str, Any]:
    """
    Run a comprehensive analysis on an Ethereum contract.
    
    Args:
        address: Ethereum contract address
        network: Network to use (mainnet, goerli, sepolia)
        output_file: Optional file to save results
        skip_reentrancy: Whether to skip the reentrancy vulnerability check
        
    Returns:
        Dict containing analysis results
    """
    results = {
        'address': address,
        'network': network,
        'timestamp': import_from_file("time", "time").strftime('%Y-%m-%d %H:%M:%S')
    }
    
    print_header(f"Starting analysis of contract {address} on {network}")
    
    # Step 1: Get contract information
    print_header("Fetching contract information")
    try:
        contract_info = info_getter.get_contract_stats(address, network)
        results['contract_info'] = contract_info
        
        print(f"Contract type: {'Token' if contract_info.get('is_erc20') or contract_info.get('is_erc721') else 'Standard contract'}")
        print(f"Balance: {contract_info.get('balance_eth')} ETH")
        
        if contract_info.get('is_erc20'):
            token_info = contract_info.get('token_info', {})
            if token_info:
                print(f"Token: {token_info.get('name')} ({token_info.get('symbol')})")
                print(f"Total Supply: {token_info.get('total_supply')}")
                print(f"Decimals: {token_info.get('decimals')}")
        
        if contract_info.get('is_proxy'):
            print_warning("Contract appears to be a proxy")
            
        bytecode = contract_info.get('bytecode', '')
        if not bytecode or bytecode == '0x':
            print_error("No bytecode found. This might not be a contract address.")
            return results
            
    except Exception as e:
        print_error(f"Error fetching contract info: {str(e)}")
        import traceback
        traceback.print_exc()
        return results

    # Step 2: Disassemble bytecode
    print_header("Disassembling bytecode")
    try:
        instructions, function_sigs, security_info = bytecode_analyzer.disassemble(bytecode)
        results['disassembly'] = {
            'instructions': instructions[:100],  # Limit output size
            'function_signatures': function_sigs
        }
        
        # Add security info to results
        results['security_info'] = security_info
        
        print(f"Identified {len(function_sigs)} function signatures")
        sig_count = min(len(function_sigs), 10)
        if sig_count > 0:
            print("Top function signatures:")
            for i, (sig, name) in enumerate(list(function_sigs.items())[:sig_count], 1):
                print(f"  {i}. 0x{sig}: {name}")
        
        # Display dangerous opcodes if found
        if security_info and security_info.get('dangerous_opcodes'):
            dangerous_opcodes = security_info['dangerous_opcodes']
            has_dangerous = any(positions for positions in dangerous_opcodes.values())
            
            if has_dangerous:
                print_warning("Potentially dangerous opcodes detected:")
                for opcode, positions in dangerous_opcodes.items():
                    if positions:
                        print(f"  - {opcode}: found at positions {', '.join(map(str, positions[:5]))}" + 
                             (f" and {len(positions)-5} more" if len(positions) > 5 else ""))
        
    except Exception as e:
        print_error(f"Error disassembling bytecode: {str(e)}")
        import traceback
        traceback.print_exc()
        return results

    # Step 3: Check for reentrancy vulnerabilities
    if skip_reentrancy:
        print_header("Skipping reentrancy vulnerability check (disabled by user)")
        results['reentrancy_findings'] = []
    else:
        print_header("Checking for reentrancy vulnerabilities")
        findings = check_reentrancy(instructions, function_sigs, contract_info)
        results['reentrancy_findings'] = findings
        
        if findings:
            print_warning(f"Found {len(findings)} potential reentrancy issues:")
            for finding in findings:
                print(f"  - {finding}")
        else:
            print_success("No obvious reentrancy vulnerabilities detected.")
    
    # Step 4: Analyze contract relationships
    print_header("Analyzing contract relationships")
    try:
        relations = contract_relations.analyze_contract_relations(bytecode)
        results['relationships'] = relations
        
        # Print human-readable output
        if relations['child_indicators']:
            print_warning("Found child contract creation operations:")
            for op in relations['creation_ops']:
                print(f"  - {op['opcode']} at position {op['position']}")
        else:
            print_success("No direct child contract creation operations detected")
        
        # Display proxy information if detected
        if relations.get('proxy_indicators'):
            print_warning("Proxy contract indicators detected:")
            if relations.get('proxy_signatures'):
                print("  Function signatures indicating proxy:")
                for sig in relations.get('proxy_signatures', []):
                    print(f"  - 0x{sig.get('selector')}: {sig.get('signature')}")
            if relations.get('clone_pattern_detected'):
                print("  EIP-1167 minimal proxy pattern detected")
        
        if relations['parent_candidates']:
            print("Potential parent/implementation contracts:")
            for addr in relations['parent_candidates']:
                print(f"  - {addr}")
    except Exception as e:
        print_error(f"Error analyzing contract relationships: {str(e)}")
        import traceback
        traceback.print_exc()
        # Continue with other analyses even if this one fails
    
    # Step 5: Decode relationships
    try:
        decoded = contract_relations.decode_bytecode_relationships(bytecode)
        results['decoded_relationships'] = decoded
        
        if decoded['decoded'] and decoded['implementation_addresses']:
            print("\nPotential implementation addresses found in bytecode:")
            for addr in decoded['implementation_addresses']:
                print(f"  - {addr}")
    except Exception as e:
        print_error(f"Error decoding relationships: {str(e)}")
    
    # Save results to file if requested
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print_success(f"Results saved to {output_file}")
    
    print_header("Analysis complete")
    return results

def analyze_bytecode(address: str, network: str = 'mainnet'):
    """Analyze only the bytecode of a contract."""
    try:
        contract_info = info_getter.get_contract_stats(address, network)
        bytecode = contract_info.get('bytecode', '')
        if not bytecode or bytecode == '0x':
            print_error("No bytecode found.")
            return
            
        instructions, function_sigs, security_info = bytecode_analyzer.disassemble(bytecode)
        print_header("Disassembly")
        for instr in instructions[:50]:  # Print first 50 instructions
            print(instr)
            
        print_header("Function Signatures")
        for sig, name in function_sigs.items():
            print(f"0x{sig}: {name}")
            
        # Display dangerous opcodes if found
        if security_info and security_info.get('dangerous_opcodes'):
            dangerous_opcodes = security_info['dangerous_opcodes']
            has_dangerous = any(positions for positions in dangerous_opcodes.values())
            
            if has_dangerous:
                print_warning("Potentially dangerous opcodes detected:")
                for opcode, positions in dangerous_opcodes.items():
                    if positions:
                        print(f"  - {opcode}: found at {len(positions)} location(s)")
    except Exception as e:
        print_error(f"Error: {str(e)}")

def analyze_relations(address: str, network: str = 'mainnet'):
    """Analyze only the relationships of a contract."""
    try:
        contract_info = info_getter.get_contract_stats(address, network)
        bytecode = contract_info.get('bytecode', '')
        if not bytecode or bytecode == '0x':
            print_error("No bytecode found.")
            return
            
        print_header("Contract Relationship Analysis")
        relations = contract_relations.analyze_contract_relations(bytecode)
        
        if relations['child_indicators']:
            print_warning("Child contract creation operations:")
            for op in relations['creation_ops']:
                print(f"  - {op['opcode']} at position {op['position']}")
        else:
            print_success("No direct child contract creation operations detected")
        
        if relations.get('proxy_indicators'):
            print_warning("Proxy contract indicators detected:")
            if relations.get('proxy_signatures'):
                print("  Function signatures indicating proxy:")
                for sig in relations.get('proxy_signatures', []):
                    print(f"  - 0x{sig.get('selector')}: {sig.get('signature')}")
            if relations.get('clone_pattern_detected'):
                print("  EIP-1167 minimal proxy pattern detected")
        
        if relations['parent_candidates']:
            print("Potential parent/implementation contracts:")
            for addr in relations['parent_candidates']:
                print(f"  - {addr}")
        
        # Also show decoded relationships
        decoded = contract_relations.decode_bytecode_relationships(bytecode)
        if decoded['decoded'] and decoded['implementation_addresses']:
            print("\nPotential implementation addresses found in bytecode:")
            for addr in decoded['implementation_addresses']:
                print(f"  - {addr}")
    except Exception as e:
        print_error(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description='Ethereum Security Toolkit')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Full analysis command
    full_parser = subparsers.add_parser('analyze', help='Run full contract analysis')
    full_parser.add_argument('address', help='Contract address to analyze')
    full_parser.add_argument('-n', '--network', default='mainnet', 
                      help='Blockchain network (mainnet, goerli, sepolia)')
    full_parser.add_argument('-o', '--output', help='Save results to JSON file')
    
    # Reentrancy check command
    reentrancy_parser = subparsers.add_parser('reentrancy', help='Check for reentrancy vulnerabilities')
    reentrancy_parser.add_argument('address', help='Contract address to check')
    reentrancy_parser.add_argument('-n', '--network', default='mainnet', 
                           help='Blockchain network (mainnet, goerli, sepolia)')
    
    # Bytecode analysis command
    bytecode_parser = subparsers.add_parser('bytecode', help='Analyze contract bytecode')
    bytecode_parser.add_argument('address', help='Contract address to analyze')
    bytecode_parser.add_argument('-n', '--network', default='mainnet', 
                           help='Blockchain network (mainnet, goerli, sepolia)')
    
    # Relationship analysis command
    relation_parser = subparsers.add_parser('relations', help='Analyze contract relationships')
    relation_parser.add_argument('address', help='Contract address to analyze')
    relation_parser.add_argument('-n', '--network', default='mainnet',
                          help='Blockchain network (mainnet, goerli, sepolia)')
    
    # Popular contracts command
    popular_parser = subparsers.add_parser('popular', help='Analyze popular Ethereum contracts')
    popular_parser.add_argument('-l', '--list', action='store_true', 
                         help='List popular contracts')
    popular_parser.add_argument('-n', '--number', 
                         help='Number of the popular contract to analyze')
    popular_parser.add_argument('-t', '--type', default='analyze', choices=['analyze', 'reentrancy', 'bytecode', 'relations'],
                         help='Type of analysis to perform')
    popular_parser.add_argument('--network', default='mainnet',
                         help='Blockchain network (mainnet, goerli, sepolia)')
    popular_parser.add_argument('-o', '--output', 
                         help='Save results to JSON file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'analyze':
        run_full_analysis(args.address, args.network, args.output)
    elif args.command == 'reentrancy':
        # Just run the reentrancy part of the full analysis
        print("Running reentrancy vulnerability check...")
        run_full_analysis(args.address, args.network)
        # The reentrancy results are already printed in run_full_analysis
    elif args.command == 'bytecode':
        analyze_bytecode(args.address, args.network)
    elif args.command == 'relations':
        analyze_relations(args.address, args.network)
    elif args.command == 'popular':
        if args.list or not args.number:
            display_popular_contracts()
            # If just listing, exit after displaying
            if not args.number:
                return
        
        analyze_popular_contract(args.number, args.type, args.network, args.output)

if __name__ == "__main__":
    main() 