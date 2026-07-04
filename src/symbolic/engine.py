import angr
import claripy

class SymbolicEngine:
    """
    An educational wrapper around angr's symbolic execution engine.
    Designed to expose step-by-step path exploration and constraint generation.
    """
    def __init__(self, binary_loader):
        self.project = binary_loader.project
        # Initialize a basic state at the entry point
        self.state = self.project.factory.entry_state()
        # Initialize the simulation manager to track execution paths
        self.simgr = self.project.factory.simulation_manager(self.state)
        
        self.execution_trace = []
        self.step_count = 0

    def inject_symbolic_input(self, name="sym_input", size_bytes=32):
        """
        Demonstrates injecting a symbolic variable (e.g., standard input).
        """
        sym_var = claripy.BVS(name, size_bytes * 8)
        # Re-initialize the state and simgr with the symbolic input on stdin
        self.state = self.project.factory.entry_state(stdin=sym_var)
        self.simgr = self.project.factory.simulation_manager(self.state)
        return sym_var

    def step(self):
        """
        Advances the symbolic execution by one step (typically a basic block)
        and records the path constraints for educational visualization.
        """
        if not self.simgr.active:
            return False

        # Step all active paths forward
        self.simgr.step()
        self.step_count += 1
        
        step_data = {
            'step': self.step_count,
            'active_states': [],
            'deadended_states': len(self.simgr.deadended)
        }

        # Extract educational data from every active path (state)
        for idx, state in enumerate(self.simgr.active):
            addr = state.addr
            
            # Extract the mathematical path constraints generated so far
            constraints = state.solver.constraints
            constraint_strings = [str(c) for c in constraints]
            
            state_info = {
                'state_id': idx,
                'address': hex(addr),
                'constraints': constraint_strings,
                'is_satisfiable': state.solver.satisfiable()
            }
            step_data['active_states'].append(state_info)
            
        self.execution_trace.append(step_data)
        return True

    def explore(self, max_steps=50):
        """
        Explores paths up to a maximum depth to prevent path explosion,
        returning the trace of constraints and states.
        """
        steps = 0
        while self.simgr.active and steps < max_steps:
            self.step()
            steps += 1
            
        return self.execution_trace

    def print_trace(self):
        """
        Utility to print the recorded execution trace to the terminal.
        """
        print(f"--- Symbolic Execution Trace ({self.step_count} steps) ---")
        for step in self.execution_trace:
            print(f"\nStep {step['step']}:")
            print(f"  Active Paths: {len(step['active_states'])}")
            print(f"  Deadended Paths: {step['deadended_states']}")
            for st in step['active_states']:
                print(f"    -> Path {st['state_id']} @ {st['address']}")
                print(f"       Constraints: {st['constraints']}")
                print(f"       Satisfiable: {st['is_satisfiable']}")
