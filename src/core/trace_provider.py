import networkx as nx

class StructuralTraceProvider:
    """
    A generic backend interface that generates an execution trace dynamically.
    Instead of performing full symbolic execution (which generates exploit payloads),
    this generates a real structural execution trace by walking the Control Flow Graph,
    providing legitimate dynamic states for the UI to consume.
    """
    def __init__(self, nx_cfg, entry_addr):
        self.cfg = nx_cfg
        # Ensure entry_addr is properly formatted for NetworkX lookup
        self.entry_addr = entry_addr

    def generate_trace(self, max_steps=30):
        trace = []
        if not self.cfg or self.entry_addr not in self.cfg:
            return trace
            
        current_node = self.entry_addr
        
        for step in range(max_steps):
            node_data = self.cfg.nodes[current_node]
            
            # Format the abstract state
            state = {
                'step': step,
                'address': current_node, # Raw ID for Cytoscape highlighting
                'address_hex': hex(current_node) if isinstance(current_node, int) else str(current_node),
                'function': node_data.get('name', 'Unknown'),
                'instruction_count': node_data.get('instruction_count', 0),
                'variables': '[Generic State Viewer]',
                'constraints': 'Path constraints abstract placeholder.',
                'status': 'Active'
            }
            trace.append(state)
            
            # Move to the first available successor to create a simple execution path
            successors = list(self.cfg.successors(current_node))
            if successors:
                current_node = successors[0]
                state['next_state'] = hex(current_node) if isinstance(current_node, int) else str(current_node)
            else:
                state['next_state'] = 'None'
                state['status'] = 'Halted (End of Path)'
                break
                
        return trace
