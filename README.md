# Neuro-Symbolic Fuzzer - Educational Module

An educational Binary Analysis and Symbolic Verification platform.
Demonstrates Control Flow Graph (CFG) extraction, Call Graph generation, and step-by-step symbolic execution using `angr` and `z3`.

## Features
- Ghidra-style interactive graph visualization using Dash and Cytoscape.
- Step-by-step symbolic execution trace.
- Z3 constraint extraction and educational plain-English explanations.
- Rich node metadata for future Graph Neural Network (GNN) integration.

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python main.py path/to/binary
```
