import z3
import claripy

class Z3Interface:
    """
    An educational module demonstrating how symbolic constraints are evaluated 
    by an SMT solver (Z3) to determine the feasibility of an execution path 
    and to generate satisfying assignments (concrete inputs).
    """

    @staticmethod
    def evaluate_path(state, symbolic_variables):
        """
        Evaluates the accumulated path constraints of a given execution state dynamically
        using the actual constraints generated from the binary during symbolic execution.
        
        :param state: The current angr SimState containing real path constraints.
        :param symbolic_variables: A dictionary mapping names to claripy.BVS symbolic variables.
        :return: A dictionary containing SAT/UNSAT status and the satisfying mathematical model.
        """
        # claripy delegates the constraint solving to Z3 under the hood.
        is_sat = state.solver.satisfiable()
        
        result = {
            'status': 'SAT' if is_sat else 'UNSAT',
            'constraints_evaluated': [str(c) for c in state.solver.constraints],
            'satisfying_assignment': {}
        }
        
        # If the path constraints are satisfiable, Z3 can provide a "model" 
        # (the concrete values that satisfy the constraints).
        if is_sat and symbolic_variables:
            for name, sym_var in symbolic_variables.items():
                try:
                    # Evaluate the symbolic variable down to a concrete byte sequence
                    concrete_value = state.solver.eval(sym_var, cast_to=bytes)
                    result['satisfying_assignment'][name] = concrete_value
                except Exception as e:
                    result['satisfying_assignment'][name] = f"<Evaluation Error: {str(e)}>"
                    
        return result
