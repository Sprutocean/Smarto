#!/usr/bin/env python3
"""
Child-Parent Contract Analyzer

This module analyzes relationships between Ethereum contracts, focusing on:
1. Child contract creation (CREATE, CREATE2 opcodes)
2. Parent contract detection (contract that deployed this contract)
3. Proxy pattern detection
"""

import re
from typing import Dict, Any, List, Set, Optional

# Common proxy implementation signatures
PROXY_SIGNATURES = [
    {
        'selector': '5c60da1b',
        'signature': 'implementation()'
    },
    {
        'selector': '7050c9e0',
        'signature': 'implementation()'
    },
    {
        'selector': 'f851a440',
        'signature': 'admin()'
    },
    {
        'selector': 'aaf10f42',
        'signature': 'getImplementation()'
    }
]

# EIP-1167 Minimal Proxy Pattern - unique bytecode pattern
MINIMAL_PROXY_PATTERN = '363d3d373d3d3d363d73'
MINIMAL_PROXY_ADDRESS_REGEX = r'363d3d373d3d3d363d73([a-fA-F0-9]{40})'

def analyze_contract_relations(bytecode: str) -> Dict[str, Any]:
    """
    Analyze contract bytecode to detect child contract creation and proxy patterns.
    
    Args:
        bytecode: Contract bytecode as hex string
        
    Returns:
        Dict with analysis results
    """
    bytecode = bytecode.lower().replace('0x', '')
    result = {
        'child_indicators': False,
        'creation_ops': [],
        'parent_candidates': [],
        'proxy_indicators': False,
        'proxy_signatures': [],
        'clone_pattern_detected': False
    }
    
    # Analyze child contract creation operations
    operation_patterns = [
        {'opcode': 'CREATE', 'pattern': 'f0'},
        {'opcode': 'CREATE2', 'pattern': 'f5'}
    ]
    
    for op in operation_patterns:
        pos = 0
        while True:
            pos = bytecode.find(op['pattern'], pos)
            if pos == -1:
                break
                
            result['child_indicators'] = True
            result['creation_ops'].append({
                'opcode': op['opcode'],
                'position': pos // 2  # Convert hex position to bytecode position
            })
            pos += len(op['pattern'])
    
    # Check for EIP-1167 minimal proxy pattern
    if MINIMAL_PROXY_PATTERN in bytecode:
        result['clone_pattern_detected'] = True
        result['proxy_indicators'] = True
        
        # Extract implementation address if present
        matches = re.findall(MINIMAL_PROXY_ADDRESS_REGEX, bytecode)
        for match in matches:
            if match and all(c in '0123456789abcdef' for c in match):
                result['parent_candidates'].append(f"0x{match}")
    
    # Check for proxy function signatures
    for proxy_sig in PROXY_SIGNATURES:
        if proxy_sig['selector'] in bytecode:
            result['proxy_indicators'] = True
            result['proxy_signatures'].append(proxy_sig)
    
    # Check for DELEGATECALL opcode (common in proxies)
    if 'f4' in bytecode:
        result['proxy_indicators'] = True
    
    return result

def decode_bytecode_relationships(bytecode: str) -> Dict[str, Any]:
    """
    Decode bytecode to extract contract implementation addresses and relationships.
    
    Args:
        bytecode: Contract bytecode as hex string
        
    Returns:
        Dict with decoded relationships
    """
    bytecode = bytecode.lower().replace('0x', '')
    result = {
        'decoded': False,
        'implementation_addresses': []
    }
    
    # Look for potential addresses in the bytecode (20 bytes preceded by PUSH20)
    push20_pattern = '73'  # PUSH20 opcode
    pos = 0
    while True:
        pos = bytecode.find(push20_pattern, pos)
        if pos == -1:
            break
            
        # Extract the 20 bytes (40 hex chars) after PUSH20
        if pos + 2 + 40 <= len(bytecode):
            addr = bytecode[pos+2:pos+2+40]
            if all(c in '0123456789abcdef' for c in addr):
                result['implementation_addresses'].append(f"0x{addr}")
                result['decoded'] = True
                
        pos += 2
    
    # Look for addresses in EIP-1167 minimal proxy pattern
    matches = re.findall(MINIMAL_PROXY_ADDRESS_REGEX, bytecode)
    for match in matches:
        if match and all(c in '0123456789abcdef' for c in match):
            addr = f"0x{match}"
            if addr not in result['implementation_addresses']:
                result['implementation_addresses'].append(addr)
                result['decoded'] = True
    
    return result

def extract_deployment_addresses(bytecode: str, creation_code: bool = False) -> List[str]:
    """
    Extract potential Ethereum addresses that this contract might deploy.
    
    Args:
        bytecode: Contract bytecode
        creation_code: Whether the bytecode is creation code
        
    Returns:
        List of potential addresses
    """
    bytecode = bytecode.lower().replace('0x', '')
    addresses = []
    
    # PUSH20 followed by 20 bytes (40 hex chars)
    push20_pattern = '73'  # PUSH20 opcode
    pos = 0
    while True:
        pos = bytecode.find(push20_pattern, pos)
        if pos == -1:
            break
            
        # Extract the 20 bytes (40 hex chars) after PUSH20
        if pos + 2 + 40 <= len(bytecode):
            addr = bytecode[pos+2:pos+2+40]
            if all(c in '0123456789abcdef' for c in addr):
                addresses.append(f"0x{addr}")
                
        pos += 2
    
    return addresses

def main():
    """Example usage of the module."""
    # Example bytecode with CREATE opcode
    create_bytecode = "0x608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063f0fdf83414610046575b600080fd5b34801561005257600080fd5b5061007f6004803603602081101561006957600080fd5b81019080803590602001909291905050506100e1565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156100bf5780820151818401526020810190506100a4565b50505050905090810190601f1680156100ec5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60608173ffffffffffffffffffffffffffffffffffffffff166c01000000000000000000000000028152601401908060021c905060f0"
    
    # Example bytecode with proxy pattern
    proxy_bytecode = "0x363d3d373d3d3d363d73b4272055d58d169768eaa261966302dc5ba773e5af43d82803e903d91602b57fd5bf3"
    
    # Analyze the example bytecodes
    create_results = analyze_contract_relations(create_bytecode)
    proxy_results = analyze_contract_relations(proxy_bytecode)
    
    # Print the results
    print("CREATE Bytecode Analysis:")
    print(f"Child creation indicators: {create_results['child_indicators']}")
    print(f"Creation operations: {len(create_results['creation_ops'])}")
    
    print("\nProxy Bytecode Analysis:")
    print(f"Proxy indicators: {proxy_results['proxy_indicators']}")
    print(f"Clone pattern detected: {proxy_results['clone_pattern_detected']}")
    print(f"Parent/Implementation candidates: {proxy_results['parent_candidates']}")

if __name__ == "__main__":
    main() 