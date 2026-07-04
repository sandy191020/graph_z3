import networkx as nx

class GraphBuilder:
    def __init__(self, binary_loader):
        self.loader = binary_loader
        self.entry_addr = self.loader.project.entry

    def build_networkx_cfg(self):
        angr_cfg = self.loader.get_cfg()
        nx_graph = nx.DiGraph()

        if not angr_cfg:
            return nx_graph

        for node in angr_cfg.graph.nodes():
            if node.name:
                label = f"{node.name}\n{hex(node.addr)}"
            else:
                label = f"Block {hex(node.addr)}"
                
            # CFG Node metadata
            instr_count = len(node.instruction_addrs) if hasattr(node, 'instruction_addrs') and node.instruction_addrs else 0
            is_entry = (node.addr == self.entry_addr)
            
            node_class = 'entry' if is_entry else ('syscall' if node.is_syscall else 'internal')
                
            nx_graph.add_node(
                node.addr,
                label=label,
                name=node.name if node.name else f"sub_{hex(node.addr)}",
                addr=hex(node.addr),
                size=node.size,
                type="block",
                instruction_count=instr_count,
                node_class=node_class
            )

        for src, dst, data in angr_cfg.graph.edges(data=True):
            nx_graph.add_edge(src.addr, dst.addr)
            
        # Post-process for in/out degree
        for node in nx_graph.nodes():
            nx_graph.nodes[node]['incoming_edges'] = nx_graph.in_degree(node)
            nx_graph.nodes[node]['outgoing_edges'] = nx_graph.out_degree(node)

        return nx_graph

    def build_networkx_cg(self):
        angr_cg = self.loader.get_call_graph()
        nx_graph = nx.DiGraph()
        
        if not angr_cg:
             return nx_graph
             
        functions = self.loader.get_functions()

        for node_addr in angr_cg.nodes():
            func = functions.function(node_addr)
            if func:
                bb_count = len(func.block_addrs) if hasattr(func, 'block_addrs') else 0
                instr_count = 0
                try:
                    for b in func.blocks:
                        if hasattr(b, 'instruction_addrs'):
                            instr_count += len(b.instruction_addrs)
                except Exception:
                    pass
                
                is_lib = func.is_simprocedure or func.is_plt
                is_entry = (func.addr == self.entry_addr or func.name == 'main')
                
                if is_entry:
                    node_class = 'entry'
                elif is_lib:
                    node_class = 'library'
                else:
                    node_class = 'internal'
                 
                nx_graph.add_node(
                    node_addr,
                    label=func.name,
                    name=func.name,
                    addr=hex(func.addr),
                    size=func.size,
                    type="function",
                    basic_block_count=bb_count,
                    instruction_count=instr_count,
                    is_library_call=is_lib,
                    node_class=node_class
                )

        for src, dst in angr_cg.edges():
             nx_graph.add_edge(src, dst)

        # Post-process for in/out degree
        for node in nx_graph.nodes():
            nx_graph.nodes[node]['incoming_edges'] = nx_graph.in_degree(node)
            nx_graph.nodes[node]['outgoing_edges'] = nx_graph.out_degree(node)

        return nx_graph
