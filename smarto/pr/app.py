"""
Simple web UI for Ethereum Security Toolkit with multilingual support
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response, session, g
import os
import sys
import json
import importlib.util
from typing import Dict, Any
# Import our custom translations module
from translations import get_text, TRANSLATIONS

app = Flask(__name__)
app.secret_key = 'ethereum_security_toolkit_secret_key'  # For session management

# Available languages
LANGUAGES = {
    'en': 'English',
    'ru': 'Русский'
}

# Custom gettext function that uses our translations
def _(text):
    # Get the current language from session or default to English
    lang = g.get('lang_code', 'en')
    return get_text(text, lang)

# Define the locale selector function
def get_locale():
    # Try to get the language from the session first
    if 'language' in session:
        return session['language']
    
    # Then from the request
    if request.args.get('lang'):
        return request.args.get('lang')
    
    # Then from the cookie
    if request.cookies.get('language'):
        return request.cookies.get('language')
    
    # Default to English
    return 'en'

@app.before_request
def before_request():
    # Store the current language code in Flask g object for template access
    g.lang_code = get_locale()
    # Make translation function available in templates
    app.jinja_env.globals.update(_=_)

# Add the toolkit directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'toolkit'))

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

# Import the toolkit modules
def import_from_file(module_name, file_path):
    try:
        if not os.path.exists(file_path):
            raise ImportError(f"File {file_path} does not exist")
            
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if not spec or not spec.loader:
            raise ImportError(f"Could not load spec for {file_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"Error importing {file_path}: {str(e)}")
        return None

# Import our toolkit modules
toolkit_path = os.path.join(os.path.dirname(__file__), 'toolkit')

# Global variable to track if toolkit modules are available
TOOLKIT_AVAILABLE = False

try:
    # Attempt to import toolkit modules
    toolkit = import_from_file("ethereum_security_toolkit", 
                             os.path.join(toolkit_path, "ethereum-security-toolkit.py"))
    if toolkit:
        TOOLKIT_AVAILABLE = True
except Exception as e:
    print(f"Error importing toolkit: {str(e)}")

@app.route('/language/<lang>')
def set_language(lang):
    """Set the language preference."""
    if lang not in LANGUAGES:
        lang = 'en'
    
    # Store in session
    session['language'] = lang
    
    # Get the referrer URL or use the index route
    referrer = request.referrer or url_for('index')
    
    # Store in cookie as well
    response = make_response(redirect(referrer))
    response.set_cookie('language', lang, max_age=60*60*24*365)  # 1 year
    
    return response

@app.route('/', methods=['GET', 'POST'])
def index():
    # Default values
    contract_address = ''
    network = 'mainnet'
    analysis_type = 'analyze'
    results = {}
    results_json = ''
    error_message = None
    analysis_complete = False
    skip_reentrancy = False
    
    # Handle form submission
    if request.method == 'POST':
        # Check if toolkit is available
        if not TOOLKIT_AVAILABLE:
            error_message = "Toolkit modules are not available. Please make sure all required files are in the toolkit directory."
        else:
            # Get form data
            contract_address = request.form.get('contract_address', '')
            network = request.form.get('network', 'mainnet')
            analysis_type = request.form.get('analysis_type', 'analyze')
            skip_reentrancy = 'skip_reentrancy' in request.form
            
            # Check if a popular contract was selected
            popular_contract = request.form.get('popular_contract', '')
            if popular_contract and popular_contract in POPULAR_CONTRACTS:
                contract_address = POPULAR_CONTRACTS[popular_contract]['address']
                # For display purposes in the form
                popular_contract_selected = popular_contract
            else:
                popular_contract_selected = ''
            
            # Validate contract address
            if not contract_address:
                error_message = "Please enter a contract address"
            else:
                try:
                    # Run the appropriate analysis based on type
                    if analysis_type == 'analyze':
                        results = toolkit.run_full_analysis(contract_address, network, skip_reentrancy=skip_reentrancy)
                    elif analysis_type == 'reentrancy':
                        if skip_reentrancy:
                            error_message = "Cannot skip reentrancy check when the analysis type is reentrancy"
                        else:
                            results = toolkit.run_full_analysis(contract_address, network)
                            # Filter to just show reentrancy results
                            if 'reentrancy_findings' in results:
                                results = {'reentrancy_findings': results['reentrancy_findings']}
                    elif analysis_type == 'bytecode':
                        # Get contract info and bytecode
                        info_getter = import_from_file("info_getter", 
                                                     os.path.join(toolkit_path, "info-getter.py"))
                        bytecode_analyzer = import_from_file("bytecode_analyzer", 
                                                           os.path.join(toolkit_path, "bytecode.py"))
                        
                        if not info_getter or not bytecode_analyzer:
                            error_message = "Required modules are missing. Please make sure info-getter.py and bytecode.py exist in the toolkit directory."
                        else:
                            contract_info = info_getter.get_contract_stats(contract_address, network)
                            bytecode = contract_info.get('bytecode', '')
                            
                            if bytecode and bytecode != '0x':
                                instructions, function_sigs, security_info = bytecode_analyzer.disassemble(bytecode)
                                results = {
                                    'instructions': instructions[:100],  # Limit to first 100
                                    'function_signatures': function_sigs,
                                    'security_info': security_info  # Add security info to results
                                }
                            else:
                                error_message = "No bytecode found for this address."
                    elif analysis_type == 'relations':
                        # Get contract info and analyze relationships
                        info_getter = import_from_file("info_getter", 
                                                     os.path.join(toolkit_path, "info-getter.py"))
                        contract_relations = import_from_file("contract_relations", 
                                                            os.path.join(toolkit_path, "child-parent.py"))
                        
                        if not info_getter or not contract_relations:
                            error_message = "Required modules are missing. Please make sure info-getter.py and child-parent.py exist in the toolkit directory."
                        else:
                            contract_info = info_getter.get_contract_stats(contract_address, network)
                            bytecode = contract_info.get('bytecode', '')
                            
                            if bytecode and bytecode != '0x':
                                relations = contract_relations.analyze_contract_relations(bytecode)
                                decoded = contract_relations.decode_bytecode_relationships(bytecode)
                                results = {
                                    'relationships': relations,
                                    'decoded_relationships': decoded
                                }
                            else:
                                error_message = "No bytecode found for this address."
                                
                    # Mark analysis as complete if no errors                
                    analysis_complete = error_message is None
                    
                    # Convert results to JSON for display
                    results_json = json.dumps(results, indent=2, default=str)
                    
                except Exception as e:
                    error_message = str(e)
    
    # Render the template with all necessary data
    return render_template('index.html', 
                          popular_contracts=POPULAR_CONTRACTS,
                          toolkit_available=TOOLKIT_AVAILABLE,
                          contract_address=contract_address,
                          network=network,
                          analysis_type=analysis_type,
                          skip_reentrancy=skip_reentrancy,
                          results=results,
                          results_json=results_json,
                          error_message=error_message,
                          analysis_complete=analysis_complete,
                          languages=LANGUAGES)

if __name__ == '__main__':
    # Make sure the toolkit directory exists
    os.makedirs(os.path.join(os.path.dirname(__file__), 'toolkit'), exist_ok=True)
    
    # Create templates and static directories if they don't exist
    os.makedirs(os.path.join(os.path.dirname(__file__), 'templates'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'static'), exist_ok=True)
    
    # Provide info about toolkit availability
    if not TOOLKIT_AVAILABLE:
        print("\n=====================================================")
        print("WARNING: Toolkit modules are not fully available.")
        print("Please copy these files to the 'toolkit' directory:")
        print(" - ethereum-security-toolkit.py")
        print(" - info-getter.py")
        print(" - bytecode.py")
        print(" - reentrancy-vulnerability-checker.py")
        print(" - child-parent.py")
        print("=====================================================\n")
    
    app.run(debug=True) 