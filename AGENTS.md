# Ada Script

## 1. Project Overview
**Ada Script** is a framework for reverse engineering that can analyze executable files, emulate runtime behavior, and generate .lst and .asm files.

## 2. Purpose and Features
The primary purpose of this agent framework is to automate complex reverse engineering and analysis workflows. Key features include:

- **Modular agent architecture** - Easily extendable with new capabilities
- **Distributed task processing** - Agents can work in parallel on complex tasks
- **Cross-platform support** - Works on Windows, Linux, and macOS
- **Emulation capabilities** - Safe execution of untrusted binaries
- **Analysis pipelines** - Chain multiple agents for complex workflows


- **Analyzer Agent**: Performs static analysis of executable files
- **Emulator Agent**: Executes binaries in a controlled environment
- **Parser Agent**: Processes and structures analysis results
- **Database**: Stores analysis results and agent states

## 4. Installation and Setup

### Prerequisites
- Python 3.9+

### Installation Steps
```bash
# Clone the repository
git clone https://github.com/xor2003/ada_script.git
cd ada_script

# Install dependencies
pip install -r requirements.txt

```



## 7. Limitations and Known Issues
- Emulation of network operations is currently disabled
- Large binaries (>100MB) may cause performance issues

### Running Tests
To run the test suite:
```bash
pytest
```

### Trying the Simple Parser
To test the IDC parser with a simple file:
```bash
python -c "from idc_engine import parse_idc; print(parse_idc('f15dgtl.idc', {}))"
```

### Testing the Parser with a Complex File
To test the IDC parser with a more complex file:
```bash
python -c "from idc_engine import parse_idc; print(parse_idc('egame.idc', {}))"
```

### Real Processing Workflow
To run the full processing pipeline:
```bash
python ada.py egame.exe -s egame.idc --debug --full --classify --xrefs
```