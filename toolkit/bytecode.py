import argparse
import json
import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from typing import Dict, List, Tuple, Any, Set

import requests
import re

# EVM opcode mapping (Gray Glacier fork)
OPCODES = {
    "00": "STOP",
    "01": "ADD",
    "02": "MUL",
    "03": "SUB",
    "04": "DIV",
    "05": "SDIV",
    "06": "MOD",
    "07": "SMOD",
    "08": "ADDMOD",
    "09": "MULMOD",
    "0a": "EXP",
    "0b": "SIGNEXTEND",
    "10": "LT",
    "11": "GT",
    "12": "SLT",
    "13": "SGT",
    "14": "EQ",
    "15": "ISZERO",
    "16": "AND",
    "17": "OR",
    "18": "XOR",
    "19": "NOT",
    "1a": "BYTE",
    "1b": "SHL",
    "1c": "SHR",
    "1d": "SAR",
    "20": "SHA3",
    "30": "ADDRESS",
    "31": "BALANCE",
    "32": "ORIGIN",
    "33": "CALLER",
    "34": "CALLVALUE",
    "35": "CALLDATALOAD",
    "36": "CALLDATASIZE",
    "37": "CALLDATACOPY",
    "38": "CODESIZE",
    "39": "CODECOPY",
    "3a": "GASPRICE",
    "3b": "EXTCODESIZE",
    "3c": "EXTCODECOPY",
    "3d": "RETURNDATASIZE",
    "3e": "RETURNDATACOPY",
    "3f": "EXTCODEHASH",
    "40": "BLOCKHASH",
    "41": "COINBASE",
    "42": "TIMESTAMP",
    "43": "NUMBER",
    "44": "DIFFICULTY",
    "45": "GASLIMIT",
    "46": "CHAINID",
    "47": "SELFBALANCE",
    "48": "BASEFEE",
    "50": "POP",
    "51": "MLOAD",
    "52": "MSTORE",
    "53": "MSTORE8",
    "54": "SLOAD",
    "55": "SSTORE",
    "56": "JUMP",
    "57": "JUMPI",
    "58": "PC",
    "59": "MSIZE",
    "5a": "GAS",
    "5b": "JUMPDEST",
    "5f": "PUSH0",
    "60": "PUSH1",
    "61": "PUSH2",
    "62": "PUSH3",
    "63": "PUSH4",
    "64": "PUSH5",
    "65": "PUSH6",
    "66": "PUSH7",
    "67": "PUSH8",
    "68": "PUSH9",
    "69": "PUSH10",
    "6a": "PUSH11",
    "6b": "PUSH12",
    "6c": "PUSH13",
    "6d": "PUSH14",
    "6e": "PUSH15",
    "6f": "PUSH16",
    "70": "PUSH17",
    "71": "PUSH18",
    "72": "PUSH19",
    "73": "PUSH20",
    "74": "PUSH21",
    "75": "PUSH22",
    "76": "PUSH23",
    "77": "PUSH24",
    "78": "PUSH25",
    "79": "PUSH26",
    "7a": "PUSH27",
    "7b": "PUSH28",
    "7c": "PUSH29",
    "7d": "PUSH30",
    "7e": "PUSH31",
    "7f": "PUSH32",
    "80": "DUP1",
    "81": "DUP2",
    "82": "DUP3",
    "83": "DUP4",
    "84": "DUP5",
    "85": "DUP6",
    "86": "DUP7",
    "87": "DUP8",
    "88": "DUP9",
    "89": "DUP10",
    "8a": "DUP11",
    "8b": "DUP12",
    "8c": "DUP13",
    "8d": "DUP14",
    "8e": "DUP15",
    "8f": "DUP16",
    "90": "SWAP1",
    "91": "SWAP2",
    "92": "SWAP3",
    "93": "SWAP4",
    "94": "SWAP5",
    "95": "SWAP6",
    "96": "SWAP7",
    "97": "SWAP8",
    "98": "SWAP9",
    "99": "SWAP10",
    "9a": "SWAP11",
    "9b": "SWAP12",
    "9c": "SWAP13",
    "9d": "SWAP14",
    "9e": "SWAP15",
    "9f": "SWAP16",
    "a0": "LOG0",
    "a1": "LOG1",
    "a2": "LOG2",
    "a3": "LOG3",
    "a4": "LOG4",
    "f0": "CREATE",
    "f1": "CALL",
    "f2": "CALLCODE",
    "f3": "RETURN",
    "f4": "DELEGATECALL",
    "f5": "CREATE2",
    "fa": "STATICCALL",
    "fd": "REVERT",
    "fe": "INVALID",
    "ff": "SELFDESTRUCT",
}

# Common function signatures
FUNCTION_SIGNATURES = {
    "06fdde03": "name()",
    "095ea7b3": "approve(address,uint256)",
    "18160ddd": "totalSupply()",
    "23b872dd": "transferFrom(address,address,uint256)",
    "313ce567": "decimals()",
    "70a08231": "balanceOf(address)",
    "7ecebe00": "mint(uint256)",
    "8da5cb5b": "owner()",
    "95d89b41": "symbol()",
    "a0712d68": "burn(uint256)",
    "a9059cbb": "transfer(address,uint256)",
    "dd62ed3e": "allowance(address,address)",
    "f2fde38b": "transferOwnership(address)",
    "ffa1ad74": "VERSION()",
}

# Add more common ERC20 and ERC721 signatures
FUNCTION_SIGNATURES.update(
    {
        # ERC20
        "a457c2d7": "decreaseAllowance(address,uint256)",
        "39509351": "increaseAllowance(address,uint256)",
        # ERC721
        "6352211e": "ownerOf(uint256)",
        "42842e0e": "safeTransferFrom(address,address,uint256)",
        "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
        "e985e9c5": "isApprovedForAll(address,address)",
        "2f745c59": "tokenOfOwnerByIndex(address,uint256)",
        "c87b56dd": "tokenURI(uint256)",
        # Access Control
        "9010d07c": "getRoleMember(bytes32,uint256)",
        "ca15c873": "getRoleMemberCount(bytes32)",
        "91d14854": "hasRole(bytes32,address)",
        "36568abe": "renounceRole(bytes32,address)",
        "2f2ff15d": "grantRole(bytes32,address)",
        "d547741f": "revokeRole(bytes32,address)",
    }
)

# Load signature cache from file if it exists
CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "signature_cache.json"
)
SIGNATURE_CACHE = {}

try:
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            SIGNATURE_CACHE = json.load(f)
except Exception:
    pass


def save_signature_cache():
    """Save signature cache to file."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(SIGNATURE_CACHE, f)
    except Exception:
        pass


@lru_cache(maxsize=1024)
def fetch_signature(hex_sig: str) -> str:
    """Fetch function signature from 4byte.directory API with rate limiting and caching."""
    # Check local cache first
    if hex_sig in SIGNATURE_CACHE:
        return SIGNATURE_CACHE[hex_sig]

    try:
        print(f"Fetching signature: {hex_sig}")
        response = requests.get(
            f"https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{hex_sig}",
            params={"ordering": "created_at"},
            headers={"User-Agent": "EVM-Disassembler/1.0"},
            timeout=5,
        )
        response.raise_for_status()

        data = response.json()
        signature = data["results"][0]["text_signature"] if data["count"] > 0 else ""
        print(f"Fetched signature: {signature}")
        # Update cache
        SIGNATURE_CACHE[hex_sig] = signature
        return signature

    except Exception as e:
        print(f"Error fetching signature: {e}")
    finally:
        time.sleep(0.3)  # Rate limiting


def fetch_signatures_parallel(hex_sigs: List[str]) -> Dict[str, str]:
    """Fetch multiple function signatures in parallel."""
    # Check which signatures we need to fetch
    print("Fetching signatures in parallel...")
    to_fetch = [sig for sig in hex_sigs if sig not in SIGNATURE_CACHE]
    results = {sig: SIGNATURE_CACHE.get(sig, "") for sig in hex_sigs}

    # If nothing to fetch, return cached results
    if not to_fetch:
        return results

    # Fetch in parallel with rate limiting (max 3 concurrent requests)
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_sig = {executor.submit(fetch_signature, sig): sig for sig in to_fetch}
        for future in as_completed(future_to_sig):
            sig = future_to_sig[future]
            try:
                results[sig] = future.result()
            except Exception:
                results[sig] = ""

    # Save updated cache
    save_signature_cache()
    return results


def normalize_bytecode(bytecode: str) -> str:
    """Normalize bytecode by removing 0x prefix and ensuring lowercase."""
    return bytecode.lower().strip().replace("0x", "")


def extract_function_selectors(bytecode: str) -> List[str]:
    """Extract all potential function selectors from bytecode."""
    bytecode = normalize_bytecode(bytecode)
    selectors = []

    # Look for PUSH4 operations followed by potential selectors
    i = 0
    while i < len(bytecode) - 10:  # Need at least 10 chars (PUSH4 + 4 bytes)
        if bytecode[i : i + 2] == "63":  # PUSH4
            selector = bytecode[i + 2 : i + 10]
            if len(selector) == 8 and all(c in "0123456789abcdef" for c in selector):
                selectors.append(selector)
            i += 10
        else:
            i += 2

    return selectors


def detect_dangerous_opcodes(instructions: List[str]) -> Dict[str, List[int]]:
    """
    Detect potentially dangerous opcodes in the bytecode instructions.
    
    Args:
        instructions: List of disassembled instructions
        
    Returns:
        Dict mapping dangerous opcode to list of instruction indexes where it appears
    """
    dangerous_opcodes = {
        'DELEGATECALL': [],
        'SELFDESTRUCT': [],
        'TX.ORIGIN': []
    }
    
    for idx, instr in enumerate(instructions):
        for opcode in dangerous_opcodes.keys():
            if opcode in instr.upper():
                dangerous_opcodes[opcode].append(idx)
    
    return dangerous_opcodes


def disassemble(bytecode: str) -> Tuple[List[str], Dict[str, str], Dict[str, Any]]:
    """
    Disassemble EVM bytecode and extract function signatures.
    
    Args:
        bytecode: Ethereum bytecode as hex string (with or without 0x prefix)
        
    Returns:
        Tuple of (list of instructions, dict of function signatures, dict of security info)
    """
    # Remove 0x prefix if present
    if bytecode.startswith('0x'):
        bytecode = bytecode[2:]
    
    # Normalize to lowercase
    bytecode = bytecode.lower()
    
    # Extract function signatures (simple approach)
    function_sigs = extract_function_signatures(bytecode)
    
    # Disassemble the bytecode
    instructions = []
    i = 0
    while i < len(bytecode):
        try:
            # Get the current byte as an integer
            op = int(bytecode[i:i+2], 16)
            
            # Get the opcode definition
            if op in OPCODES:
                opcode_name = OPCODES[op][0]
                gas = OPCODES[op][1]
                
                # Check for PUSH operations (these have immediate data)
                if opcode_name.startswith('PUSH'):
                    n = op - 0x5f  # PUSH1 is 0x60, PUSH2 is 0x61, etc.
                    
                    if i + 2 + (n * 2) <= len(bytecode):
                        data = bytecode[i+2:i+2+(n*2)]
                        instruction = f"{hex(i//2)} {opcode_name} 0x{data}"
                        instructions.append(instruction)
                        i += 2 + (n * 2)
                    else:
                        instruction = f"{hex(i//2)} {opcode_name} [INCOMPLETE DATA]"
                        instructions.append(instruction)
                        break
                else:
                    # Regular opcodes without immediate data
                    instruction = f"{hex(i//2)} {opcode_name}"
                    instructions.append(instruction)
                    i += 2
            else:
                # Unknown opcode
                instruction = f"{hex(i//2)} UNKNOWN (0x{bytecode[i:i+2]})"
                instructions.append(instruction)
                i += 2
        except Exception as e:
            # Handle any errors during disassembly
            instruction = f"{hex(i//2)} ERROR: {str(e)}"
            instructions.append(instruction)
            i += 2
    
    # Detect potentially dangerous opcodes
    security_info = {
        'dangerous_opcodes': detect_dangerous_opcodes(instructions)
    }
    
    return instructions, function_sigs, security_info


def main():
    """Main function to parse arguments and disassemble bytecode."""
    parser = argparse.ArgumentParser(description="EVM Bytecode Disassembler")
    parser.add_argument("input", help="Hex bytecode or file path")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show verbose output"
    )
    parser.add_argument(
        "--no-api", action="store_true", help="Skip API lookups for unknown signatures"
    )
    parser.add_argument("--output", "-o", help="Write output to file")
    args = parser.parse_args()

    try:
        # Try reading from file first
        bytecode = args.input
        if os.path.exists(args.input):
            with open(args.input, "r", encoding="utf-8") as f:
                bytecode = f.read().strip()

        instructions, sigs, security_info = disassemble(bytecode)

        # Prepare output
        output_text = ["EVM Disassembly:", "----------------\n"]
        output_text.extend(instructions)

        if sigs:
            output_text.extend(["\n\nDetected Function Signatures:"])
            for sig, name in sorted(sigs.items()):
                output_text.append(f"0x{sig}: {name}")

        if security_info['dangerous_opcodes']:
            output_text.extend(["\n\nDetected Dangerous Opcodes:"])
            for opcode, indexes in security_info['dangerous_opcodes'].items():
                output_text.append(f"{opcode}: {', '.join(map(str, indexes))}")

        # Output to file or console
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(output_text))
            print(f"Disassembly written to {args.output}")
        else:
            print("\n".join(output_text))

    except ValueError as e:
        print(f"Error: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        if args.verbose:
            traceback.print_exc()


if __name__ == "__main__":
    try:
        main()
    finally:
        # Save signature cache when exiting
        save_signature_cache()
