# Ethereum Security Toolkit UI

A simple web interface for the Ethereum Security Toolkit.

## Features

- Web-based interface for analyzing Ethereum smart contracts
- Support for all toolkit analysis types (full, reentrancy, bytecode, relationships)
- Popular contracts library integration
- Clean visualization of analysis results
- Cross-platform web interface

## Prerequisites

- Python 3.6+
- Required Python packages:
  - Flask
  - web3
  - requests

## Installation

1. Copy your existing toolkit files into the `toolkit` directory:
   - ethereum-security-toolkit.py
   - info-getter.py 
   - bytecode.py
   - reentrancy-vulnerability-checker.py
   - child-parent.py

2. Install required packages:

```bash
pip install flask web3 requests
```

## Usage

1. Start the Flask application:

```bash
python app.py
```

2. Open your web browser and navigate to:

```
http://127.0.0.1:5000/
```

3. Use the web interface to:
   - Enter an Ethereum contract address to analyze
   - Select a popular contract from the dropdown
   - Choose the type of analysis to perform
   - View the results in a formatted web page

## Project Structure

```
/ethereum-security-toolkit-ui/
    app.py                   # Flask application
    /templates/
        index.html           # Main form page
        results.html         # Results display page
        about.html           # About page
    /static/
        style.css            # Custom CSS
    /toolkit/                # Directory for toolkit scripts
        ethereum-security-toolkit.py
        info-getter.py
        bytecode.py
        reentrancy-vulnerability-checker.py
        child-parent.py
    README-UI.md             # This file
```

## Customization

- Edit the `static/style.css` file to customize the appearance
- Modify the templates in the `templates` directory to change the layout or add new features
- Update the `app.py` file to add new routes or functionality

## Limitations

- The UI runs with Flask's development server, which is not suitable for production use
- Analysis of some contracts may take time to complete
- The UI shares the same limitations as the underlying toolkit

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 