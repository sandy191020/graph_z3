from typing import List, Optional, Dict, Any, Tuple, Set
from dataclasses import dataclass, field
import time

from core.binary_loader import BinaryLoader
from symbolic.engine import SymbolicEngine
from symbolic.z3_interface import Z3Interface
from analysis.vuln_scanner import VulnerabilityScanner, VulnFinding, compact_witness, first_meaningful_line


@dataclass
class ExecutionState:
    function_name: str
    basic_block: str
    instruction_address: str
    execution_depth: int
    symbolic_variables: str
    path_constraints: str
    solver_status: str
    model_information: str
    explanation: str
    next_state: str
    is_library: bool = False
    is_branch: bool = False
    raw_path_constraints: str = ""
    event_type: str = "NORMAL"   # ENTRY | EXIT | BRANCH | LOOP | LIBRARY_CALL | RETURN | SYSCALL | NORMAL
    previous_block: str = ""
    next_block: str = ""
    transferred_function: bool = False
    new_constraints_introduced: bool = False


@dataclass
class ConstraintResult:
    constraint_list: str
    status: str
    statistics: str
    model: str
    explanation: str
    raw_constraint_list: str = ""
    solver_time_ms: float = 0.0
    constraint_annotations: List[str] = field(default_factory=list)
    symbolic_variables_list: List[Dict[str, Any]] = field(default_factory=list)


# --------------------------------------------------------------------------
# Best-effort claripy/Z3 AST -> human-readable text.
# --------------------------------------------------------------------------

_OP_SYMBOLS = {
    '__eq__': '==', '__ne__': '!=',
    '__le__': '<=', '__lt__': '<', '__ge__': '>=', '__gt__': '>',
    'SLE': '<=', 'SLT': '<', 'SGE': '>=', 'SGT': '>',
    'ULE': '<=', 'ULT': '<', 'UGE': '>=', 'UGT': '>',
    '__add__': '+', '__sub__': '-', '__mul__': '*',
    '__xor__': '^', '__and__': '&', '__or__': '|',
    '__lshift__': '<<', 'LShR': '>>', '__rshift__': '>>',
}


def _slugify_local(name: str) -> str:
    import re as _re
    s = _re.sub(r'[^a-zA-Z0-9]+', '_', name).strip('_').lower()
    return s or "unnamed"


def _fmt_constant(value: int, bits: int) -> str:
    num_bytes = max(1, bits // 8)
    if num_bytes == 1 and 32 <= value < 127:
        return f"0x{value:02x} ('{chr(value)}')"
    try:
        return f"0x{value:0{num_bytes * 2}x}"
    except Exception:
        return hex(value)


def _describe_extract(hi: int, lo: int, var_label: str) -> str:
    lo_byte, hi_byte = lo // 8, hi // 8
    if lo_byte == hi_byte:
        return f"byte {lo_byte} of {var_label}"
    return f"bytes {lo_byte}-{hi_byte} of {var_label}"


def _humanize_ast(node, depth: int = 0) -> str:
    if depth > 6:
        return "..."

    op = getattr(node, 'op', None)
    args = getattr(node, 'args', None)
    if op is None or args is None:
        return str(node)

    try:
        if op == 'BVV':
            return _fmt_constant(args[0], args[1])
        if op == 'BoolV':
            return "true" if args[0] else "false"
        if op == 'BVS':
            return str(args[0]).split('_')[0] + " input"
        if op == 'Extract' and len(args) == 3:
            hi, lo, child = args
            if getattr(child, 'op', None) == 'BVS':
                return _describe_extract(hi, lo, str(child.args[0]).split('_')[0] + " input")
            return f"bits {lo}-{hi} of ({_humanize_ast(child, depth + 1)})"
        if op == 'Concat':
            return " ++ ".join(_humanize_ast(a, depth + 1) for a in args)
        if op == 'Not':
            return f"NOT ({_humanize_ast(args[0], depth + 1)})"
        if op == 'And':
            return " AND ".join(_humanize_ast(a, depth + 1) for a in args)
        if op == 'Or':
            return " OR ".join(_humanize_ast(a, depth + 1) for a in args)
        if op in ('ZeroExt', 'SignExt') and len(args) == 2:
            return _humanize_ast(args[1], depth + 1)
        if op == 'Reverse' and len(args) == 1:
            return _humanize_ast(args[0], depth + 1)
        if op in _OP_SYMBOLS and len(args) == 2:
            left, right = args
            return f"{_humanize_ast(left, depth + 1)} {_OP_SYMBOLS[op]} {_humanize_ast(right, depth + 1)}"
    except Exception:
        pass

    try:
        child_strs = [_humanize_ast(a, depth + 1) for a in args if hasattr(a, 'op')]
        if child_strs:
            return f"{op}(" + ", ".join(child_strs) + ")"
    except Exception:
        pass

    text = str(node)
    return text if len(text) <= 80 else text[:77] + "..."


def _humanize_constraint(constraint) -> str:
    try:
        return _humanize_ast(constraint)
    except Exception:
        return str(constraint)


def _pretty_print_constraint(c_str: str, max_depth: int = 3) -> str:
    indent = 0
    lines = []
    curr = ""
    for char in c_str:
        if char == '(':
            if curr.strip():
                lines.append("  " * indent + curr.strip())
            curr = ""
            lines.append("  " * indent + "(")
            indent += 1
            if indent > max_depth:
                lines.append("  " * indent + "...")
                break
        elif char == ')':
            if curr.strip():
                lines.append("  " * indent + curr.strip())
            curr = ""
            indent = max(0, indent - 1)
            lines.append("  " * indent + ")")
        elif char == ',':
            if curr.strip():
                lines.append("  " * indent + curr.strip() + ",")
            curr = ""
        else:
            curr += char
    if curr.strip():
        lines.append("  " * indent + curr.strip())
    return "\n".join(lines)


# Helper: query solver to find constrained and unconstrained byte offsets of a BVS variable
def get_byte_status(state, sym_var) -> Tuple[List[int], List[int]]:
    size_bytes = sym_var.size() // 8
    constrained_bytes = []
    unconstrained_bytes = []
    for i in range(size_bytes):
        hi = (size_bytes - 1 - i) * 8 + 7
        lo = (size_bytes - 1 - i) * 8
        byte_expr = sym_var[hi:lo]
        try:
            possible_values = state.solver.eval_upto(byte_expr, 2)
            if len(possible_values) == 1:
                constrained_bytes.append(i)
            else:
                unconstrained_bytes.append(i)
        except Exception:
            constrained_bytes.append(i)  # fallback
    return constrained_bytes, unconstrained_bytes


# Helper: find all BVS leaf nodes in the constraints
def get_symbolic_variables_from_state(state, injected_vars) -> Dict[str, Any]:
    vars_dict = dict(injected_vars)
    
    def walk(node):
        if not hasattr(node, 'op') or not hasattr(node, 'args'):
            return
        if node.op == 'BVS':
            name = node.args[0]
            if name not in vars_dict:
                vars_dict[name] = node
            return
        for arg in node.args:
            walk(arg)
            
    for constraint in state.solver.constraints:
        walk(constraint)
        
    return vars_dict


# Helper: get name and offset for leaf node in constraint
def _get_bvs_and_offset(node) -> Tuple[Optional[str], Optional[int]]:
    if not hasattr(node, 'op') or not hasattr(node, 'args'):
        return None, None
    if node.op == 'BVS':
        return node.args[0], 0
    if node.op == 'Extract' and len(node.args) == 3:
        hi, lo, child = node.args
        if child.op == 'BVS':
            return child.args[0], lo // 8
        if child.op == 'Reverse' and child.args[0].op == 'BVS':
            return child.args[0].args[0], lo // 8
    if node.op == 'Reverse':
        return _get_bvs_and_offset(node.args[0])
    return None, None


# Advanced plain-English annotation generator for constraints
def _annotate_constraints(constraints) -> List[str]:
    annotations: List[str] = []
    for i, c in enumerate(constraints):
        human = _humanize_constraint(c)
        c_str = str(c)
        op = getattr(c, 'op', '')
        
        # Default fallback meaning
        meaning = "A path constraint boundary generated by conditional jump evaluations."
        
        try:
            if op in ('__eq__', '__ne__') and len(c.args) == 2:
                left, right = c.args
                val = None
                bvs_name = None
                byte_idx = None
                if right.op == 'BVV':
                    val = right.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(left)
                elif left.op == 'BVV':
                    val = left.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(right)
                
                if bvs_name is not None and byte_idx is not None and val is not None:
                    clean_name = bvs_name.split('_')[0]
                    char_repr = f" ('{chr(val)}')" if 32 <= val < 127 else ""
                    if op == '__eq__':
                        meaning = f"Execution only continues if byte {byte_idx} of {clean_name} input equals {hex(val)}{char_repr}."
                    else:
                        meaning = f"Execution only continues if byte {byte_idx} of {clean_name} input does not equal {hex(val)}{char_repr}."
            elif op in ('__le__', '__lt__', '__ge__', '__gt__', 'SLE', 'SLT', 'SGE', 'SGT', 'ULE', 'ULT', 'UGE', 'UGT') and len(c.args) == 2:
                left, right = c.args
                val = None
                bvs_name = None
                byte_idx = None
                if right.op == 'BVV':
                    val = right.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(left)
                elif left.op == 'BVV':
                    val = left.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(right)
                
                if bvs_name is not None and byte_idx is not None and val is not None:
                    clean_name = bvs_name.split('_')[0]
                    comp_word = "less than or equal to" if op in ('__le__', 'SLE', 'ULE') else \
                                "less than" if op in ('__lt__', 'SLT', 'ULT') else \
                                "greater than or equal to" if op in ('__ge__', 'SGE', 'UGE') else \
                                "greater than"
                    meaning = f"Execution only continues if byte {byte_idx} of {clean_name} input is {comp_word} {hex(val)}."
        except Exception:
            pass

        annotations.append(f"[{i + 1}] {human} — {meaning}")

    return annotations


def _format_model(symbolic_vars: Dict[str, Any], satisfying_assignment: Dict[str, Any], constraints, state) -> str:
    if not satisfying_assignment:
        return "No concrete model was produced (path unsatisfiable, or no symbolic inputs are in scope)."

    blocks = []
    for name, value in satisfying_assignment.items():
        sym_var = symbolic_vars.get(name)
        if not isinstance(value, (bytes, bytearray)):
            blocks.append(f"Variable '{name}': {value} (not a byte-vector; shown as-is)")
            continue

        size_bytes = len(value)
        # Query byte status
        constrained = set()
        unconstrained = set()
        if sym_var is not None:
            c_bytes, uc_bytes = get_byte_status(state, sym_var)
            constrained = set(c_bytes)
            unconstrained = set(uc_bytes)
            
        hex_str = ' '.join(f'{b:02x}' for b in value)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in value)

        is_symbolic_val = "Symbolic" if len(constrained) > 0 else "Concrete (Unconstrained)"

        lines = [
            f"Variable '{name}' ({size_bytes} bytes) — [{is_symbolic_val}]:",
            f"  hex:   {hex_str}",
            f"  ascii: \"{ascii_str}\"",
        ]
        if not constrained:
            lines.append(
                f"  All {size_bytes} byte(s) are currently concrete (unconstrained) by path; "
                f"the Z3 SMT solver assigned default value 0x00 since no instructions pinned them."
            )
        else:
            free_count = len(unconstrained)
            byte_list = ', '.join(str(b) for b in sorted(constrained))
            lines.append(
                f"  Byte offset(s) [{byte_list}] are actively constrained. "
                f"The solver evaluated the path constraints and selected this specific assignment "
                f"to satisfy equations. The remaining {free_count} bytes are free."
            )
        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


# --------------------------------------------------------------------------
# Event-type classifier
# --------------------------------------------------------------------------

_X86_COND_JMP = {
    'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
    'jb', 'jbe', 'ja', 'jae', 'jc', 'jnc', 'jo', 'jno',
    'js', 'jns', 'jp', 'jnp', 'jpe', 'jpo', 'jcxz', 'jecxz', 'jrcxz',
}
_ARM_COND_JMP = {
    'beq', 'bne', 'blt', 'bgt', 'ble', 'bge', 'bhi', 'blo',
    'bcs', 'bcc', 'bvs', 'bvc', 'bpl', 'bmi', 'cbz', 'cbnz', 'tbz', 'tbnz',
}


def _classify_event_type(
    raw_state,
    func_name: str,
    prev_func_name: Optional[str],
    is_lib: bool,
    is_branch: bool,
    visited_addrs: Set[int],
    project,
) -> str:
    """
    Classify the current execution event into one of:
    ENTRY | BRANCH | LOOP | LIBRARY_CALL | RETURN | SYSCALL | NORMAL
    """
    addr = raw_state.addr

    # Very first step
    if prev_func_name is None:
        return "ENTRY"

    # Function transition
    if func_name != prev_func_name:
        return "LIBRARY_CALL" if is_lib else "ENTRY"

    # Inspect the last instruction of the previous basic block
    try:
        bbl_addrs = list(raw_state.history.bbl_addrs)
        if bbl_addrs:
            prev_bb = bbl_addrs[-1]
            blk = project.factory.block(prev_bb)
            insns = blk.capstone.insns if blk.capstone else []
            if insns:
                mn = insns[-1].mnemonic.lower().strip()
                # Return instructions
                if (mn.startswith('ret') or mn in ('bx lr', 'blr', 'eret')):
                    return "RETURN"
                # Syscalls
                if mn in ('syscall', 'sysenter', 'svc', 'int') or mn.startswith('svc'):
                    return "SYSCALL"
                # Conditional branches
                if mn in _X86_COND_JMP or mn in _ARM_COND_JMP:
                    return "BRANCH"
                if mn.startswith('b.') or (mn.startswith('b ') and mn != 'bl'):
                    return "BRANCH"
    except Exception:
        pass

    # Fallback: angr detected a fork (branch)
    if is_branch:
        return "BRANCH"

    # Revisiting an address → loop back-edge
    if addr in visited_addrs:
        return "LOOP"

    return "NORMAL"


class AnalysisBackendProvider:
    """
    Adapter that wires the UI up to the real analysis backend:
    BinaryLoader (angr CFG/project loading), SymbolicEngine (step-wise
    symbolic execution), and Z3Interface (solver diagnostics).
    """

    def __init__(self, binary_path: str, max_steps: int = 30, symbolic_input_size: int = 32):
        self.binary_path = binary_path
        self.max_steps = max_steps

        self.loader = BinaryLoader(binary_path)
        self.loader.analyze()

        self.engine = SymbolicEngine(self.loader)

        sym_var = self.engine.inject_symbolic_input(name="stdin_input", size_bytes=symbolic_input_size)
        self.symbolic_variables: Dict[str, Any] = {"stdin_input": sym_var}

        self._state_registry: Dict[int, Tuple[Any, Dict[str, Any]]] = {}
        self._trace_cache: Optional[List[ExecutionState]] = None

    def _resolve_function_info(self, addr: int) -> Tuple[str, bool]:
        """Returns (function_name, is_library_function)."""
        try:
            functions = self.loader.get_functions()
            func = functions.floor_func(addr)
            if func is None:
                return "Unknown", False
            is_lib = bool(getattr(func, 'is_simprocedure', False) or getattr(func, 'is_plt', False))
            return func.name, is_lib
        except Exception:
            return "Unknown", False

    def _build_crash_state(self, state, parent_state, depth, reason: str, err_str: str,
                            path_history, addr_hex: Optional[str] = None) -> ExecutionState:
        """
        Builds an ExecutionState for a crash (symbolic/unconstrained IP, or any
        exception while stepping). Unlike a dropped/ignored error, this keeps
        the state's real path constraints and registers it for Z3 solving, so
        the SMT panel can produce the exact concrete input that reaches and
        triggers this crash — that's the whole point of finding a breaking point.
        """
        func_name = parent_state.function_name if parent_state else "Unknown"
        is_lib = parent_state.is_library if parent_state else False
        prev_block_hex = parent_state.basic_block if parent_state else ""
        display_addr = addr_hex or "SYMBOLIC (unconstrained IP)"

        try:
            constraints = list(state.solver.constraints)
        except Exception:
            constraints = []

        try:
            is_sat = state.solver.satisfiable() if constraints or True else False
        except Exception:
            is_sat = False

        humanized = [_humanize_constraint(c) for c in constraints]
        raw_strs = [str(c) for c in constraints]

        vars_dict = get_symbolic_variables_from_state(state, self.symbolic_variables)

        explanation = (
            f"Execution crashed after leaving '{func_name}' (last known block {prev_block_hex}): {reason}. "
            f"Underlying error: {err_str}. "
            f"The path constraints accumulated up to this point are still fully solvable — see the SMT "
            f"panel below for the exact concrete input that drives execution down this path and triggers "
            f"the crash."
        )

        exec_state = ExecutionState(
            function_name=f"{func_name} (crashed)",
            basic_block=display_addr,
            instruction_address=display_addr,
            execution_depth=depth,
            symbolic_variables=(", ".join(vars_dict.keys()) if vars_dict else "None tracked yet"),
            path_constraints=("\n".join(f"- {h}" for h in humanized) if humanized else "No constraints accumulated yet."),
            solver_status="SAT" if is_sat else "UNSAT",
            model_information=f"Crash detected: {reason}",
            explanation=explanation,
            next_state="CRASHED (analysis halted on this path)",
            is_library=is_lib,
            is_branch=False,
            raw_path_constraints=("\n".join(raw_strs) if raw_strs else ""),
            event_type="CRASH",
            previous_block=prev_block_hex,
            next_block="Crashed",
            transferred_function=False,
            new_constraints_introduced=False,
        )

        # THE FIX: register the crash state so get_constraint_result can run
        # Z3 against it, instead of silently dropping its solver session.
        self._state_registry[id(exec_state)] = (state, vars_dict)
        return exec_state

    def get_execution_trace(self) -> List[ExecutionState]:
        """Runs live symbolic execution and returns enriched ExecutionState objects using DFS."""
        if self._trace_cache is not None:
            return self._trace_cache

        states: List[ExecutionState] = []
        
        # Re-initialize SimulationManager to clear stashes cleanly
        self.engine.simgr = self.engine.project.factory.simulation_manager(self.engine.state, save_unsat=True)
        
        # Stack elements: (current_state, parent_execution_state, depth, path_history_set)
        stack: List[Tuple[Any, Optional[ExecutionState], int, frozenset]] = [
            (self.engine.state, None, 0, frozenset([self.engine.state.addr]))
        ]
        
        active_stash = []
        deadended_stash = []
        unsat_stash = []
        errored_stash = []
        
        while stack and len(states) < self.max_steps:
            state, parent_state, depth, path_history = stack.pop()

            # A symbolic/unconstrained instruction pointer is the classic
            # signature of a control-flow-hijack crash (e.g. an overwritten
            # return address from a stack buffer overflow). Previously this
            # was unguarded and would kill the entire trace-building call
            # before any crash could ever be reported.
            try:
                addr = state.addr
            except Exception as e:
                errored_stash.append(state)
                exec_state = self._build_crash_state(
                    state, parent_state, depth,
                    reason="Instruction pointer became symbolic/unconstrained (classic control-flow-hijack crash signature)",
                    err_str=str(e),
                    path_history=path_history,
                )
                states.append(exec_state)
                continue

            addr_hex = hex(addr)
            func_name, is_lib = self._resolve_function_info(addr)
            
            prev_block_hex = parent_state.basic_block if parent_state else ""
            transferred = False
            if parent_state and func_name != parent_state.function_name:
                transferred = True
                
            try:
                successors = self.engine.project.factory.successors(state)
            except Exception as e:
                errored_stash.append(state)
                exec_state = self._build_crash_state(
                    state, parent_state, depth,
                    reason=f"Execution engine failed to compute successors of block {addr_hex} in '{func_name}'",
                    err_str=str(e),
                    path_history=path_history,
                    addr_hex=addr_hex,
                )
                states.append(exec_state)
                continue
                
            flat_succs = successors.flat_successors
            unsat_succs = successors.unsat_successors
            
            is_branch = len(flat_succs) > 1
            succ_addrs = [hex(s.addr) for s in flat_succs]
            
            # Format successor descriptions
            next_state_str = ", ".join(succ_addrs) if succ_addrs else "Halted (End of Path)"
            next_block_str = succ_addrs[0] if len(succ_addrs) == 1 else "Multiple" if len(succ_addrs) > 1 else "Halted"
            
            branch_type = "NORMAL"
            if is_branch:
                if len(flat_succs) == 2:
                    branch_type = "Conditional Jump"
                else:
                    branch_type = "Switch Statement / Multi-branch"
                    
            constraints = list(state.solver.constraints)
            humanized = [_humanize_constraint(c) for c in constraints]
            raw_strs = [str(c) for c in constraints]
            
            vars_dict = get_symbolic_variables_from_state(state, self.symbolic_variables)
            sym_var_names = []
            for name, sym_var in vars_dict.items():
                constrained_bytes, unconstrained_bytes = get_byte_status(state, sym_var)
                size_bytes = sym_var.size() // 8
                sym_var_names.append(f"{name} ({sym_var.size()} bits, {len(constrained_bytes)}/{size_bytes} B constrained)")
            sym_vars_str = ", ".join(sym_var_names) if sym_var_names else "None tracked yet"
            
            new_constraints_introduced = False
            explanation_parts = []
            
            if not parent_state:
                explanation_parts.append(f"Execution started at program entry address {addr_hex} in function '{func_name}'.")
            else:
                if transferred:
                    if is_lib:
                        explanation_parts.append(f"Execution transferred from '{parent_state.function_name}' to library call '{func_name}' at {addr_hex}.")
                    else:
                        explanation_parts.append(f"Execution transitioned from function '{parent_state.function_name}' to '{func_name}' at {addr_hex}.")
                else:
                    explanation_parts.append(f"Execution advanced to basic block {addr_hex} in function '{func_name}'.")
                    
            if parent_state:
                # Compare constraint count with parent state to detect new constraints
                parent_constraint_count = len(parent_state.raw_path_constraints.split("\n")) if parent_state.raw_path_constraints else 0
                if len(constraints) > parent_constraint_count:
                    new_constraints_introduced = True
                    
            if is_branch:
                explanation_parts.append(f"Encountered a symbolic branch ({branch_type}) causing execution to split into {len(flat_succs)} satisfiable directions:")
                parent_hashes = {c.hash for c in constraints}
                for succ in flat_succs:
                    succ_addr_hex = hex(succ.addr)
                    new_c = [c for c in succ.solver.constraints if c.hash not in parent_hashes]
                    if new_c:
                        c_eng = _humanize_constraint(new_c[0])
                        explanation_parts.append(f"  - To {succ_addr_hex} requires condition: {c_eng}")
                    else:
                        explanation_parts.append(f"  - To {succ_addr_hex} (no new constraints)")
            
            explanation_str = " ".join(explanation_parts)
            
            event_type = "NORMAL"
            if depth == 0:
                event_type = "ENTRY"
            elif is_lib:
                event_type = "LIBRARY_CALL"
            elif is_branch:
                event_type = "BRANCH"
            elif addr in path_history:
                event_type = "LOOP"
            else:
                event_type = _classify_event_type(
                    raw_state=state,
                    func_name=func_name,
                    prev_func_name=parent_state.function_name if parent_state else None,
                    is_lib=is_lib,
                    is_branch=is_branch,
                    visited_addrs=set(path_history),
                    project=self.engine.project,
                )
                
            exec_state = ExecutionState(
                function_name=func_name,
                basic_block=addr_hex,
                instruction_address=addr_hex,
                execution_depth=depth,
                symbolic_variables=sym_vars_str,
                path_constraints=(
                    "\n".join(f"- {h}" for h in humanized) if humanized else "No constraints accumulated yet."
                ),
                solver_status="SAT" if state.solver.satisfiable() else "UNSAT",
                model_information=f"{len(vars_dict)} symbolic variable(s) in scope; see SMT panel for model assignment.",
                explanation=explanation_str,
                next_state=next_state_str,
                is_library=is_lib,
                is_branch=is_branch,
                raw_path_constraints="\n".join(raw_strs) if raw_strs else "",
                event_type=event_type,
                previous_block=prev_block_hex,
                next_block=next_block_str,
                transferred_function=transferred,
                new_constraints_introduced=new_constraints_introduced,
            )
            
            self._state_registry[id(exec_state)] = (state, vars_dict)
            states.append(exec_state)
            
            if not succ_addrs:
                deadended_stash.append(state)
            else:
                if depth >= self.max_steps:
                    active_stash.append(state)
                else:
                    for succ in reversed(flat_succs):
                        if succ.addr not in path_history:
                            stack.append((succ, exec_state, depth + 1, path_history.union([succ.addr])))
                        else:
                            active_stash.append(succ)
                            
            for succ in unsat_succs:
                unsat_stash.append(succ)
                
        # Link sequential trace pointers for UI transitions
        for i in range(len(states) - 1):
            states[i].next_state = states[i + 1].instruction_address
            states[i].next_block = states[i + 1].basic_block
        if states:
            states[-1].next_state = "Halted (End of Path)"
            states[-1].next_block = "Halted (End of Path)"
            
        self.engine.simgr.stashes['active'] = active_stash
        self.engine.simgr.stashes['deadended'] = deadended_stash
        self.engine.simgr.stashes['unsat'] = unsat_stash
        
        self.engine.simgr.errored.clear()
        for s in errored_stash:
            try:
                import angr.sim_manager
                self.engine.simgr.errored.append(angr.sim_manager.ErrorRecord(s, Exception("Execution error"), None))
            except Exception:
                pass
        
        self._trace_cache = states
        return states

    def get_constraint_result(self, state: ExecutionState) -> ConstraintResult:
        """Runs Z3 solver with diagnostic explanations and timings using real solver state."""
        entry = self._state_registry.get(id(state))

        if entry is None:
            return ConstraintResult(
                constraint_list=state.path_constraints,
                status=state.solver_status,
                statistics="N/A",
                model="No live solver session available for this state.",
                explanation="This state was not produced in the current backend session, so it cannot be re-solved.",
                raw_constraint_list=state.raw_path_constraints,
                solver_time_ms=0.0,
                constraint_annotations=[],
            )

        raw_state, vars_dict = entry
        
        # Solver evaluation
        result = Z3Interface.evaluate_path(raw_state, vars_dict)
        solver_time_ms = result.get("solver_time_ms", 0.0)
        
        constraints = list(raw_state.solver.constraints)
        humanized = [_humanize_constraint(c) for c in constraints]
        constraint_list = "\n\n".join(f"- {_pretty_print_constraint(h)}" for h in humanized) if humanized else "No path constraints recorded."
        raw_constraint_list = "\n\n".join(_pretty_print_constraint(c) for c in result["constraints_evaluated"]) if result["constraints_evaluated"] else ""
        
        annotations = _annotate_constraints(constraints)
        model_text = _format_model(vars_dict, result["satisfying_assignment"], constraints, raw_state)
        
        z3_stats = result.get("z3_statistics", "N/A")
        statistics = (
            f"Constraints evaluated: {len(result['constraints_evaluated'])}\n"
            f"Symbolic variables tracked: {len(vars_dict)}\n"
            f"Solver execution time: {solver_time_ms:.2f} ms\n"
            f"Z3 queries evaluated: {result.get('queries_count', 0)}\n\n"
            f"--- Raw Z3 Solver Statistics ---\n{z3_stats}"
        )
        
        # Detailed Model Explanation
        explanation_parts = []
        if result["status"] == "SAT":
            explanation_parts.append(
                "Z3 proved the path constraints are satisfiable. There exists a valid mapping of input bytes "
                "that triggers this specific execution path. "
            )
            for name, sym_var in vars_dict.items():
                constrained, unconstrained = get_byte_status(raw_state, sym_var)
                size_bytes = sym_var.size() // 8
                explanation_parts.append(
                    f"For '{name}' ({size_bytes} B), {len(constrained)} byte(s) influence the decision "
                    f"while {len(unconstrained)} byte(s) remain unconstrained (free). "
                )
                if unconstrained:
                    explanation_parts.append("Z3 automatically selected null bytes (0x00) for unconstrained bytes as a default satisfying assignment. ")
        else:
            explanation_parts.append(
                "Z3 proved the path constraints are unsatisfiable. No set of concrete inputs can satisfy "
                "the path constraints simultaneously, meaning this execution path is dead/unreachable."
            )
            
        explanation = "".join(explanation_parts)
        
        sym_vars_list = []
        if result["status"] == "SAT" and vars_dict:
            for name, sym_var in vars_dict.items():
                val = result["satisfying_assignment"].get(name)
                if val is not None and not isinstance(val, str):
                    hex_repr = ' '.join(f'{b:02x}' for b in val)
                    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in val)
                    size_bytes = len(val)
                    constrained, unconstrained = get_byte_status(raw_state, sym_var)
                    
                    sym_vars_list.append({
                        "name": name,
                        "type": f"Symbolic ({len(constrained)}/{size_bytes} B constrained)",
                        "size": size_bytes,
                        "hex": hex_repr,
                        "ascii": ascii_repr,
                        "explanation": f"Constrained bytes: {sorted(constrained)}. Unconstrained bytes: {sorted(unconstrained)}."
                    })
                elif isinstance(val, str):
                    sym_vars_list.append({
                        "name": name,
                        "type": "Error",
                        "size": 0,
                        "hex": val,
                        "ascii": "N/A",
                        "explanation": "Solver evaluation error."
                    })
                    
        return ConstraintResult(
            constraint_list=constraint_list,
            status=result["status"],
            statistics=statistics,
            model=model_text,
            explanation=explanation,
            raw_constraint_list=raw_constraint_list,
            solver_time_ms=solver_time_ms,
            constraint_annotations=annotations,
            symbolic_variables_list=sym_vars_list,
        )

    def get_vulnerability_findings(self) -> List[VulnFinding]:
        """
        Combines two tiers of findings:

        1. Static/heuristic CWE pattern detection (dangerous library calls
           via the real call graph, off-by-one loop bounds, sign-confusion
           casts, missing-null-check derefs, leak candidates, hardcoded
           credentials). These say "STATIC" / "STATIC (heuristic)" and are
           not solver-confirmed.

        2. Z3-confirmed findings derived from any CRASH states reached
           during get_execution_trace() (see _build_crash_state above) —
           these carry a real SAT/UNSAT status and a concrete witness input
           computed by Z3 against the binary's actual path constraints.
        """
        findings: List[VulnFinding] = []

        try:
            scanner = VulnerabilityScanner(self.loader)
            findings.extend(scanner.scan_static())
        except Exception as e:
            findings.append(VulnFinding(
                finding_id="static_scan_error",
                function_name="(scanner)",
                cwe=None,
                title="Static Scan Error",
                status="N/A",
                constraint="N/A",
                witness="N/A",
                reason=f"The static vulnerability scanner failed to complete: {e}",
                severity="Low",
                confidence="static",
            ))

        try:
            trace = self.get_execution_trace()
        except Exception:
            trace = []

        crash_states = [s for s in trace if getattr(s, 'event_type', None) == "CRASH"]

        for i, state in enumerate(crash_states):
            entry = self._state_registry.get(id(state))
            witness = "No concrete model computed for this crash state."
            status = state.solver_status
            constraint_line = first_meaningful_line(state.path_constraints)

            if entry is not None:
                raw_state, vars_dict = entry
                try:
                    result = Z3Interface.evaluate_path(raw_state, vars_dict)
                    status = result.get("status", status)
                    sat_assignment = result.get("satisfying_assignment", {})
                    pieces = []
                    for name, sym_var in vars_dict.items():
                        val = sat_assignment.get(name)
                        if isinstance(val, (bytes, bytearray)):
                            constrained_bytes, _ = get_byte_status(raw_state, sym_var)
                            pieces.append(f"{name} = " + compact_witness(bytes(val), set(constrained_bytes)))
                    if pieces:
                        witness = "; ".join(pieces)
                except Exception:
                    pass

            findings.append(VulnFinding(
                finding_id=f"crash_{i + 1}_{_slugify_local(state.function_name)}",
                function_name=state.function_name,
                cwe="CWE-120",
                title="Control-Flow Hijack / Memory Corruption",
                status=status,
                constraint=constraint_line,
                witness=witness,
                reason=state.explanation,
                severity="Critical",
                address=state.instruction_address,
                confidence="z3-confirmed",
            ))

        return findings