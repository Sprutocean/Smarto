#!/usr/bin/env python3
import json
import argparse
import importlib.util
import sys
import os
from typing import Dict, List, Tuple, Any, Optional

# Import functions from the scripts using their file paths
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
        print(f"Error importing {file_path}: {str(e)}")
        sys.exit(1)

# Import the modules
info_getter = import_from_file("info_getter", "info-getter.py")
bytecode_analyzer = import_from_file("bytecode_analyzer", "bytecode.py")
child_parent = import_from_file("child_parent", "child-parent.py")

# Get the functions we need
get_contract_stats = info_getter.get_contract_stats
disassemble = bytecode_analyzer.disassemble
analyze_contract_relations = child_parent.analyze_contract_relations
decode_bytecode_relationships = child_parent.decode_bytecode_relationships

def format_token_data(token_info: Dict[str, Any]) -> str:
    """Format token information into a readable string."""
    if not token_info:
        return "Unknown token"
    
    name = token_info.get('name', 'Unknown')
    symbol = token_info.get('symbol', 'Unknown')
    decimals = token_info.get('decimals', 18)
    total_supply = token_info.get('total_supply', 0)
    
    if total_supply and decimals:
        try:
            # Format the total supply with proper decimal placement
            adjusted_supply = total_supply / (10 ** decimals)
            if adjusted_supply >= 1_000_000_000:
                supply_str = f"{adjusted_supply / 1_000_000_000:.2f} billion"
            elif adjusted_supply >= 1_000_000:
                supply_str = f"{adjusted_supply / 1_000_000:.2f} million"
            else:
                supply_str = f"{adjusted_supply:,.2f}"
        except:
            supply_str = str(total_supply)
    else:
        supply_str = "Unknown"
    
    return f"{name} ({symbol}), {supply_str} tokens with {decimals} decimals"

def analyze_contract(address: str, network: str = 'mainnet', verbose: bool = False) -> Dict[str, Any]:
    """
    Complete Ethereum contract analysis in one step:
    1. Get contract information and bytecode
    2. Disassemble bytecode to assembly
    3. Analyze contract relationships
    
    Args:
        address: Ethereum contract address
        network: Network to use (mainnet, goerli, sepolia)
        verbose: Whether to print detailed output
        
    Returns:
        Dict containing all analysis results
    """
    results = {
        'address': address,
        'network': network,
        'analysis_complete': False
    }
    
    print(f"🔍 Analyzing contract {address} on {network}...")
    
    # Step 1: Get contract information
    print("\n📊 Fetching contract information...")
    try:
        contract_info = get_contract_stats(address, network)
        results['contract_info'] = contract_info
        
        if verbose:
            print(f"Contract type: {'Token' if contract_info.get('is_erc20') or contract_info.get('is_erc721') else 'Standard contract'}")
            print(f"Balance: {contract_info.get('balance_eth')} ETH")
            
            # Enhanced token info display
            if contract_info.get('is_erc20'):
                token_info = contract_info.get('token_info', {})
                print(f"Token info: {format_token_data(token_info)}")
            
            if contract_info.get('is_erc721'):
                nft_info = contract_info.get('nft_info', {})
                print(f"NFT info: {nft_info.get('name', 'Unknown')} ({nft_info.get('symbol', 'Unknown')})")
            
            if contract_info.get('is_proxy'):
                print("📝 Contract appears to be a proxy")
            
            # Display extracted strings if available
            if verbose and 'extracted_strings' in contract_info:
                print("📌 Extracted strings from bytecode:")
                for s in contract_info['extracted_strings'][:5]:  # Show top 5 strings
                    print(f"  - {s}")
        
        bytecode = contract_info.get('bytecode', '')
        if not bytecode or bytecode == '0x':
            print("❌ No bytecode found. This might not be a contract address.")
            return results
            
    except ConnectionError as e:
        print(f"❌ Network connection error: {str(e)}")
        return results
    except ValueError as e:
        print(f"❌ Invalid contract address or network: {str(e)}")
        return results
    except Exception as e:
        print(f"❌ Error fetching contract info: {str(e)}")
        import traceback
        traceback.print_exc()
        return results

    # Step 2: Disassemble bytecode
    print("\n📝 Disassembling bytecode...")
    try:
        instructions, function_sigs, security_info = disassemble(bytecode)
        results['disassembly'] = {
            'instructions': instructions,
            'function_signatures': function_sigs
        }
        
        # Add security info to results
        results['security_info'] = security_info
        
        if verbose:
            print(f"Identified {len(function_sigs)} function signatures")
            
            # Only show first 10 signatures if there are many
            display_sigs = list(function_sigs.items())
            if len(display_sigs) > 10 and not verbose:
                display_sigs = display_sigs[:10]
                print(f"  (Showing first 10 of {len(function_sigs)} signatures)")
            
            for sig, name in display_sigs:
                print(f"  - 0x{sig}: {name}")
            
            # Display dangerous opcodes if found
            if security_info and security_info.get('dangerous_opcodes'):
                dangerous_opcodes = security_info['dangerous_opcodes']
                has_dangerous = any(positions for positions in dangerous_opcodes.values())
                
                if has_dangerous:
                    print("\n⚠️ Potentially dangerous opcodes detected:")
                    for opcode, positions in dangerous_opcodes.items():
                        if positions:
                            print(f" - {opcode}: found at {len(positions)} location(s)")
            
    except ValueError as e:
        print(f"❌ Invalid bytecode format: {str(e)}")
        return results
    except Exception as e:
        print(f"❌ Error disassembling bytecode: {str(e)}")
        import traceback
        traceback.print_exc()
        return results

    # Step 3: Analyze contract relationships
    print("\n🔗 Analyzing contract relationships...")
    try:
        relations = analyze_contract_relations(bytecode)
        results['relationships'] = relations
        
        # Print human-readable output
        if relations['child_indicators']:
            print("Found child creation operations:")
            for op in relations['creation_ops']:
                print(f" - {op['opcode']} at PC {op['position']}")
        else:
            print("No direct child contract creation operations detected")
        
        # Display proxy information if detected
        if relations.get('proxy_indicators'):
            print("🔄 Proxy contract indicators detected:")
            if relations.get('proxy_signatures'):
                print("  Proxy function signatures:")
                for sig in relations.get('proxy_signatures', []):
                    print(f"  - 0x{sig.get('selector')}: {sig.get('signature')}")
            if relations.get('clone_pattern_detected'):
                print("  EIP-1167 minimal proxy pattern detected")
        
        if relations['parent_candidates']:
            print("Potential parent contracts:")
            for addr in relations['parent_candidates']:
                print(f" - {addr}")
                
                # If verbose, recursively analyze parent contract (1 level only)
                if verbose and len(relations['parent_candidates']) <= 3:  # Limit to avoid too many API calls
                    print(f"\n↑ Basic info for potential parent {addr}:")
                    try:
                        parent_info = get_contract_stats(addr, network)
                        print(f"  Type: {'Token' if parent_info.get('is_erc20') or parent_info.get('is_erc721') else 'Standard contract'}")
                        if parent_info.get('is_erc20'):
                            print(f"  Token: {format_token_data(parent_info.get('token_info', {}))}")
                        if parent_info.get('is_erc721'):
                            print(f"  NFT: {parent_info.get('nft_info', {}).get('name', 'Unknown')}")
                    except Exception:
                        print(f"  Could not fetch parent information")
        else:
            print("No parent addresses found")
            
    except Exception as e:
        print(f"❌ Error analyzing contract relationships: {str(e)}")
        import traceback
        traceback.print_exc()
        return results
    
    # Mark analysis as complete
    results['analysis_complete'] = True
    
    # Final summary
    print("\n✅ Analysis complete!")
    print(f"Contract type: {'Token' if contract_info.get('is_erc20') or contract_info.get('is_erc721') else 'Standard contract'}")
    if contract_info.get('is_erc20'):
        print(f"Token details: {format_token_data(contract_info.get('token_info', {}))}")
    if contract_info.get('is_proxy'):
        print("Proxy functionality detected")
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Comprehensive Ethereum Contract Analyzer')
    parser.add_argument('address', help='Contract address to analyze')
    parser.add_argument('-n', '--network', default='mainnet', 
                      help='Blockchain network (mainnet, goerli, sepolia)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show more detailed output')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('-r', '--recursive', action='store_true',
                      help='Recursively analyze parent contracts (experimental)')
    
    args = parser.parse_args()
    
    try:
        results = analyze_contract(args.address, args.network, args.verbose)
        
        # Experimental: Recursive analysis of parent contracts
        if args.recursive and results.get('relationships', {}).get('parent_candidates'):
            results['parent_analysis'] = {}
            for parent in results['relationships']['parent_candidates'][:2]:  # Limit to 2 parents
                print(f"\n📊 Recursively analyzing parent contract {parent}...")
                parent_results = analyze_contract(parent, args.network, False)  # Don't use verbose for parents
                results['parent_analysis'][parent] = parent_results
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n✅ Results saved to {args.output}")
            
    except KeyboardInterrupt:
        print("\n⚠️ Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 