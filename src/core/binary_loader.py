import angr
import networkx as nx

class BinaryLoader:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        self.cfg = None
        self.cg = None

    def analyze(self):
        print(f"Analyzing {self.binary_path}...")
        # Generate CFG
        self.cfg = self.project.analyses.CFGFast()
        # Call graph is accessible via the knowledge base
        self.cg = self.project.kb.functions.callgraph
        print("Analysis complete.")

    def get_cfg(self):
        return self.cfg

    def get_call_graph(self):
        return self.cg
        
    def get_functions(self):
        return self.project.kb.functions
