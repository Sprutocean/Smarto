import json
import os
import time
from web3 import Web3
from functools import lru_cache
from typing import Dict, Any, List, Optional

# Configuration 
INFURA_API_KEY = '85439f8bca734a478c40eae10d35d4d6'

# Global cache for Web3 connections
web3_connections = {}

# Common ERC20 function signatures
ERC20_SIGNATURES = {
    '06fdde03': 'name()',
    '95d89b41': 'symbol()',
    '313ce567': 'decimals()',
    '18160ddd': 'totalSupply()',
    '70a08231': 'balanceOf(address)',
    'a9059cbb': 'transfer(address,uint256)',
    '23b872dd': 'transferFrom(address,address,uint256)',
    'dd62ed3e': 'allowance(address,address)',
    '095ea7b3': 'approve(address,uint256)'
}

# Common ERC721 function signatures
ERC721_SIGNATURES = {
    '06fdde03': 'name()',
    '95d89b41': 'symbol()',
    '80ac58cd': 'supportsInterface(bytes4)',  # ERC165 check for ERC721
    '5b5e139f': 'supportsInterface(bytes4)',  # ERC165 check for ERC721Metadata
    '01ffc9a7': 'supportsInterface(bytes4)',  # ERC165 general
    '6352211e': 'ownerOf(uint256)',
    '42842e0e': 'safeTransferFrom(address,address,uint256)'
}

def get_web3(network='mainnet'):
    """Get cached Web3 connection for the specified network."""
    if network in web3_connections:
        return web3_connections[network]
    
    networks = {
        'mainnet': 'mainnet',
        'goerli': 'goerli',
        'sepolia': 'sepolia'
    }
    
    if network not in networks:
        raise ValueError(f"Unsupported network. Choose from: {', '.join(networks.keys())}")
    
    # Connect to Infura
    endpoint = f"https://{networks[network]}.infura.io/v3/{INFURA_API_KEY}"
    w3 = Web3(Web3.HTTPProvider(endpoint))
    
    # Check connection
    if not w3.is_connected():
        raise ConnectionError(f"Failed to connect to Infura at {endpoint}")
    
    print(f"Connected to Ethereum {network}")
    
    # Cache the connection
    web3_connections[network] = w3
    return w3

def extract_function_selectors(bytecode: str) -> List[str]:
    """Extract 4-byte function selectors from contract bytecode."""
    bytecode = bytecode.lower().replace('0x', '')
    selectors = []
    
    i = 0
    while i < len(bytecode) - 10:  # Need at least PUSH4 + selector (10 chars)
        if bytecode[i:i+2] == "63":  # PUSH4 opcode
            selector = bytecode[i+2:i+10]
            if len(selector) == 8 and all(c in "0123456789abcdef" for c in selector):
                selectors.append(selector)
            i += 10
        else:
            i += 2
    
    return selectors

def extract_strings_from_bytecode(bytecode: str) -> List[str]:
    """Extract string literals from bytecode."""
    bytecode = bytecode.lower().replace('0x', '')
    strings = []
    
    # Looking for patterns like PUSH1 0x20 DUP1 MSTORE ... MSTORE which often indicate strings
    i = 0
    while i < len(bytecode) - 100:  # Need enough space for a reasonable string
        if bytecode[i:i+6] == "604052":  # PUSH1 0x40 MSTORE pattern
            # Find potential UTF-8 encoded text - this is simplified and not comprehensive
            chunk = bytecode[i:i+200]
            try:
                # Convert hex pairs to bytes and try to decode as UTF-8
                for j in range(0, len(chunk), 2):
                    if j + 40 > len(chunk):
                        break
                    byte_chunk = bytes.fromhex(chunk[j:j+40])
                    text = byte_chunk.decode('utf-8', errors='ignore')
                    if len(text) > 3 and text.isprintable() and not text.isspace():
                        strings.append(text)
            except:
                pass
        i += 2
    
    return strings

def detect_contract_type(bytecode: str) -> Dict[str, Any]:
    """Detect contract type based on function selectors in bytecode."""
    result = {
        'is_erc20': False,
        'is_erc721': False,
        'function_selectors': []
    }
    
    selectors = extract_function_selectors(bytecode)
    result['function_selectors'] = selectors
    
    # Extract possible contract name/symbol from bytecode
    strings = extract_strings_from_bytecode(bytecode)
    if strings:
        result['extracted_strings'] = strings
    
    # Check for ERC20
    erc20_matches = sum(1 for s in selectors if s in ERC20_SIGNATURES)
    if erc20_matches >= 5:  # If contract has at least 5 ERC20 functions
        result['is_erc20'] = True
        
    # Check for ERC721
    erc721_matches = sum(1 for s in selectors if s in ERC721_SIGNATURES)
    if erc721_matches >= 3:  # If contract has at least 3 ERC721 functions
        result['is_erc721'] = True
    
    return result

def detect_proxy_pattern(bytecode: str) -> bool:
    """Detect if contract is likely a proxy by looking for DELEGATECALL patterns."""
    bytecode = bytecode.lower().replace('0x', '')
    # Check for DELEGATECALL opcode
    if 'f4' in bytecode:
        return True
    
    # Check for minimal proxy pattern (EIP-1167)
    minimal_proxy_pattern = "363d3d373d3d3d363d73"
    if minimal_proxy_pattern in bytecode:
        return True
        
    return False

def try_call_function(w3: Web3, contract_address: str, signature: str, return_type: str) -> Optional[Any]:
    """Try to call a read-only function on a contract."""
    try:
        # Create function selector
        selector = w3.keccak(text=signature)[:4].hex()
        
        # Call the function
        result = w3.eth.call({
            'to': contract_address,
            'data': selector
        })
        
        # Decode result based on return type
        if return_type == 'string':
            # For string, try to extract the data
            try:
                # Simple string decoding - not comprehensive
                if len(result) > 96:
                    string_start = int.from_bytes(result[64:96], byteorder='big')
                    string_length = int.from_bytes(result[32:64], byteorder='big')
                    if 0 < string_length < 100:  # Reasonable string length
                        offset = 96 + string_start
                        end = offset + string_length
                        if end <= len(result):
                            return result[offset:end].decode('utf-8', errors='ignore')
            except:
                pass
            return "(string data)"
        elif return_type == 'uint256':
            return int.from_bytes(result, byteorder='big')
        elif return_type == 'bool':
            return bool(int.from_bytes(result, byteorder='big'))
        else:
            return result.hex()
    except Exception as e:
        return None

@lru_cache(maxsize=32)
def get_contract_stats(contract_address, network='mainnet'):
    """
    Get comprehensive stats for an Ethereum contract using only on-chain data.
    
    Args:
        contract_address: The Ethereum contract address
        network: Network to use (mainnet, goerli, sepolia)
        
    Returns:
        Dict with contract information
    """
    # Input validation
    if not Web3.is_address(contract_address):
        raise ValueError(f"Invalid Ethereum address: {contract_address}")
    
    # Connect to Web3
    w3 = get_web3(network)

    # Validate and format address
    contract_address = Web3.to_checksum_address(contract_address)

    # Basic contract information
    contract_info = {
        'address': contract_address,
        'is_contract': False,
        'balance_wei': w3.eth.get_balance(contract_address),
        'transaction_count': w3.eth.get_transaction_count(contract_address),
        'bytecode': w3.eth.get_code(contract_address).hex(),
        'network': network,
        'block_number': w3.eth.block_number
    }

    # Check if it's a contract
    contract_info['is_contract'] = len(contract_info['bytecode']) > 2

    # If not a contract, return early
    if not contract_info['is_contract']:
        contract_info['balance_eth'] = Web3.from_wei(contract_info['balance_wei'], 'ether')
        return contract_info

    # Analyze contract type based on bytecode
    contract_type = detect_contract_type(contract_info['bytecode'])
    contract_info.update(contract_type)
    
    # Check if contract is likely a proxy
    contract_info['is_proxy'] = detect_proxy_pattern(contract_info['bytecode'])
    
    # Extract token name and symbol from strings if possible
    token_name = None
    token_symbol = None
    
    if 'extracted_strings' in contract_info:
        # Look for possible name/symbol in extracted strings
        for s in contract_info['extracted_strings']:
            if len(s) > 2 and len(s) < 30:
                if not token_name or len(token_name) < len(s):
                    token_name = s
            elif len(s) <= 6 and not token_symbol:
                token_symbol = s
    
    # If it's likely an ERC20, try to get token info
    if contract_info.get('is_erc20'):
        name_result = try_call_function(w3, contract_address, 'name()', 'string')
        symbol_result = try_call_function(w3, contract_address, 'symbol()', 'string')
        
        # If we got string data from the contract, use it over extracted strings
        if name_result and name_result != "(string data)":
            token_name = name_result
        
        if symbol_result and symbol_result != "(string data)":
            token_symbol = symbol_result
            
        token_info = {
            'name': token_name or "(string data)",
            'symbol': token_symbol or "(string data)",
            'decimals': try_call_function(w3, contract_address, 'decimals()', 'uint256') or 18,
            'total_supply': try_call_function(w3, contract_address, 'totalSupply()', 'uint256') or 0
        }
        contract_info['token_info'] = token_info
    
    # If it's likely an ERC721, try to get NFT info
    elif contract_info.get('is_erc721'):
        name_result = try_call_function(w3, contract_address, 'name()', 'string')
        symbol_result = try_call_function(w3, contract_address, 'symbol()', 'string')
        
        # If we got string data from the contract, use it over extracted strings
        if name_result and name_result != "(string data)":
            token_name = name_result
        
        if symbol_result and symbol_result != "(string data)":
            token_symbol = symbol_result
            
        nft_info = {
            'name': token_name or "(string data)",
            'symbol': token_symbol or "(string data)",
            'supports_metadata': try_call_function(w3, contract_address, 'supportsInterface(bytes4)', 'bool')
        }
        contract_info['nft_info'] = nft_info

    # Convert wei to ether
    contract_info['balance_eth'] = Web3.from_wei(contract_info['balance_wei'], 'ether')

    return contract_info

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Get contract information from blockchain')
    parser.add_argument('address', help='Contract address')
    parser.add_argument('-n', '--network', default='mainnet', 
                      help='Blockchain network (mainnet, goerli, sepolia)')
    parser.add_argument('--raw', action='store_true',
                      help='Include raw bytecode in output')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Show detailed output')
    
    args = parser.parse_args()
    
    try:
        stats = get_contract_stats(args.address, args.network)
        
        # Clean up output for better readability
        if not args.raw and 'bytecode' in stats and len(stats['bytecode']) > 100:
            bytecode_len = len(stats['bytecode'])
            stats['bytecode'] = f"{stats['bytecode'][:100]}... ({bytecode_len//2} bytes)"
            
        if not args.verbose and 'function_selectors' in stats:
            stats['function_selectors_count'] = len(stats['function_selectors'])
            del stats['function_selectors']
            
        if 'extracted_strings' in stats and not args.verbose:
            del stats['extracted_strings']
        
        print(json.dumps(stats, indent=2, default=str))
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {str(e)}")