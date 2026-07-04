import json
import networkx as nx


class GraphBuilder:
    def __init__(self, binary_loader):
        self.loader = binary_loader
        self.entry_addr = self.loader.project.entry

    # ── Control Flow Graph ────────────────────────────────────────────────────

    def build_networkx_cfg(self):
        angr_cfg = self.loader.get_cfg()
        nx_graph = nx.DiGraph()

        if not angr_cfg:
            return nx_graph

        for node in angr_cfg.graph.nodes():
            if node.name:
                label = f"{node.name}\n{hex(node.addr)}"
            else:
                label = f"Block\n{hex(node.addr)}"

            instr_count = (
                len(node.instruction_addrs)
                if hasattr(node, 'instruction_addrs') and node.instruction_addrs
                else 0
            )
            is_entry = node.addr == self.entry_addr
            node_class = 'entry' if is_entry else ('syscall' if node.is_syscall else 'internal')

            # Find the section of the binary containing this block
            section_name = ".text"
            try:
                sec = self.loader.project.loader.find_section_containing(node.addr)
                if sec:
                    section_name = sec.name
            except Exception:
                pass

            nx_graph.add_node(
                node.addr,
                label=label,
                name=node.name if node.name else f"sub_{hex(node.addr)}",
                addr=hex(node.addr),
                size=getattr(node, 'size', 0),
                type="block",
                instruction_count=instr_count,
                node_class=node_class,
                is_loop_header=False,
                binary_section=section_name,
            )

        for src, dst, _ in angr_cfg.graph.edges(data=True):
            if src.addr in nx_graph and dst.addr in nx_graph:
                nx_graph.add_edge(src.addr, dst.addr)

        # Post-process: degree and loop-header detection
        for node in nx_graph.nodes():
            nx_graph.nodes[node]['incoming_edges'] = nx_graph.in_degree(node)
            nx_graph.nodes[node]['outgoing_edges'] = nx_graph.out_degree(node)

        # Detect loop headers via cycles
        try:
            loop_headers = set()
            for cycle in nx.simple_cycles(nx_graph):
                if cycle:
                    loop_headers.add(cycle[0])
            for node in loop_headers:
                if node in nx_graph.nodes:
                    nx_graph.nodes[node]['is_loop_header'] = True
        except Exception:
            pass

        return nx_graph

    # ── Call Graph ────────────────────────────────────────────────────────────

    def build_networkx_cg(self):
        angr_cg = self.loader.get_call_graph()
        nx_graph = nx.DiGraph()

        if not angr_cg:
            return nx_graph

        functions = self.loader.get_functions()

        # First pass: add all nodes with their metadata
        for node_addr in angr_cg.nodes():
            func = functions.function(node_addr)
            if not func:
                continue

            bb_count = len(func.block_addrs) if hasattr(func, 'block_addrs') else 0
            instr_count = 0
            try:
                for b in func.blocks:
                    if hasattr(b, 'instruction_addrs'):
                        instr_count += len(b.instruction_addrs)
            except Exception:
                pass

            # Cyclomatic complexity
            cyclomatic = 1
            try:
                fg = func.graph
                if fg is not None:
                    n_nodes = fg.number_of_nodes()
                    n_edges = fg.number_of_edges()
                    if n_nodes > 0:
                        cyclomatic = max(1, n_edges - n_nodes + 2)
            except Exception:
                pass

            is_lib = func.is_simprocedure or func.is_plt
            is_entry = func.addr == self.entry_addr or func.name == 'main'

            if is_entry:
                node_class = 'entry'
            elif is_lib:
                node_class = 'library'
            else:
                node_class = 'internal'

            # Binary section
            section_name = ".text"
            try:
                sec = self.loader.project.loader.find_section_containing(func.addr)
                if sec:
                    section_name = sec.name
            except Exception:
                pass

            nx_graph.add_node(
                node_addr,
                label=func.name,
                name=func.name,
                addr=hex(func.addr),
                size=getattr(func, 'size', 0),
                type="function",
                basic_block_count=bb_count,
                instruction_count=instr_count,
                cyclomatic_complexity=cyclomatic,
                is_library_call=is_lib,
                is_loop_header=False,  # filled below
                node_class=node_class,
                binary_section=section_name,
                is_recursive=False,   # filled below
                callers=[],
                callees=[],
            )

        # Add edges
        for src, dst in angr_cg.edges():
            if src in nx_graph and dst in nx_graph:
                nx_graph.add_edge(src, dst)

        # Detect recursive functions (cycles containing the function node or self-loops)
        try:
            for node in nx_graph.nodes():
                # Direct recursion: self-loop
                if nx_graph.has_edge(node, node):
                    nx_graph.nodes[node]['is_recursive'] = True
                    continue
                # Indirect recursion: part of a cycle in the call graph
                for cycle in nx.simple_cycles(nx_graph):
                    if node in cycle and len(cycle) > 1:
                        nx_graph.nodes[node]['is_recursive'] = True
                        break
        except Exception:
            pass

        # Loop detection for the function's own internal CFG (not call graph)
        for node_addr in nx_graph.nodes():
            func = functions.function(node_addr)
            if func:
                try:
                    fg = func.graph
                    if fg is not None:
                        for cycle in nx.simple_cycles(fg):
                            if func.addr in cycle:
                                nx_graph.nodes[node_addr]['is_loop_header'] = True
                                break
                except Exception:
                    pass

        # Second pass: degree, callers, callees
        for node_addr in nx_graph.nodes():
            nx_graph.nodes[node_addr]['incoming_edges'] = nx_graph.in_degree(node_addr)
            nx_graph.nodes[node_addr]['outgoing_edges'] = nx_graph.out_degree(node_addr)

            # Callers
            callers = []
            for pred in nx_graph.predecessors(node_addr):
                name = nx_graph.nodes[pred].get('name', hex(pred))
                callers.append(name)
            nx_graph.nodes[node_addr]['callers'] = callers

            # Callees
            callees = []
            for succ in nx_graph.successors(node_addr):
                name = nx_graph.nodes[succ].get('name', hex(succ))
                callees.append(name)
            nx_graph.nodes[node_addr]['callees'] = callees

        return nx_graph
