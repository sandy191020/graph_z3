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
        using the raw Z3 Solver API.
        
        :param state: The current angr SimState containing real path constraints.
        :param symbolic_variables: A dictionary mapping names to claripy.BVS symbolic variables.
        :return: A dictionary containing SAT/UNSAT status, the satisfying mathematical model, and Z3 solver statistics.
        """
        import time
        t0 = time.perf_counter()
        
        # Create a raw Z3 solver
        solver = z3.Solver()
        
        # Convert Claripy constraints to raw Z3 constraints and add them to the solver
        z3_constraints = []
        for c in state.solver.constraints:
            try:
                z3_c = claripy.backends.z3.convert(c)
                solver.add(z3_c)
                z3_constraints.append(str(z3_c))
            except Exception:
                pass
                
        # Check satisfiability using raw Z3 check()
        check_result = solver.check()
        is_sat = (check_result == z3.sat)
        solver_time_ms = round((time.perf_counter() - t0) * 1000, 2)
        
        # Gather Z3 statistics
        z3_stats = solver.statistics()
        stats_str = str(z3_stats)
        
        result = {
            'status': 'SAT' if is_sat else 'UNSAT',
            'constraints_evaluated': z3_constraints if z3_constraints else [str(c) for c in state.solver.constraints],
            'satisfying_assignment': {},
            'solver_time_ms': solver_time_ms,
            'queries_count': len(state.solver.constraints),
            'z3_statistics': stats_str
        }
        
        # If satisfiable, extract values from the raw Z3 model
        if is_sat and symbolic_variables:
            z3_model = solver.model()
            for name, sym_var in symbolic_variables.items():
                try:
                    # Convert the symbolic variable to its raw Z3 AST representation
                    z3_var = claripy.backends.z3.convert(sym_var)
                    # Evaluate the variable using the Z3 model
                    z3_val = z3_model.eval(z3_var)
                    
                    # Convert the Z3 value to bytes
                    if z3.is_bv_value(z3_val):
                        val_int = z3_val.as_long()
                        size_bytes = sym_var.size() // 8
                        concrete_value = val_int.to_bytes(size_bytes, byteorder='big')
                        result['satisfying_assignment'][name] = concrete_value
                    else:
                        result['satisfying_assignment'][name] = state.solver.eval(sym_var, cast_to=bytes)
                except Exception:
                    # Fallback to claripy solver eval if direct Z3 eval fails
                    try:
                        result['satisfying_assignment'][name] = state.solver.eval(sym_var, cast_to=bytes)
                    except Exception as e:
                        result['satisfying_assignment'][name] = f"<Evaluation Error: {str(e)}>"
                    
        return result
