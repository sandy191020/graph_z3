from typing import List, Optional
from dataclasses import dataclass

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

@dataclass
class ConstraintResult:
    constraint_list: str
    status: str
    statistics: str
    model: str
    explanation: str

class AnalysisBackendProvider:
    """
    Abstract interface for connecting an external analysis backend.
    Currently acts as a stub indicating the backend is not connected.
    """
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def get_execution_trace(self) -> List[ExecutionState]:
        """Returns the sequence of execution states. Stubbed when backend is disconnected."""
        # Return a single stub state indicating disconnected status
        return [
            ExecutionState(
                function_name="Backend not connected",
                basic_block="N/A",
                instruction_address="N/A",
                execution_depth=0,
                symbolic_variables="Waiting for analysis backend.",
                path_constraints="Waiting for analysis backend.",
                solver_status="N/A",
                model_information="Waiting for analysis backend.",
                explanation="The execution trace is waiting for an external backend to connect and provide live analysis data.",
                next_state="N/A"
            )
        ]

    def get_constraint_result(self, state: ExecutionState) -> ConstraintResult:
        """Returns the solver diagnostics for a given state. Stubbed when backend is disconnected."""
        return ConstraintResult(
            constraint_list="Waiting for analysis backend.",
            status="N/A",
            statistics="Waiting for analysis backend.",
            model="Waiting for analysis backend.",
            explanation="Connect an external analysis engine to visualize solver diagnostics."
        )
