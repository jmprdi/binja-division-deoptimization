from binaryninja import SSAVariable, BinaryView, Function
from z3 import BitVecRef, BitVec
from copy import copy
from .instructions import MLILInstructionExecutor


class State:
    """
    State of the current execution
    """

    def __init__(self, bv: BinaryView, function: Function):
        self.bv = bv
        self.function = function

    def get_ssa_variable(self, variable: SSAVariable):
        raise NotImplementedError

    def set_ssa_variable(self, variable: SSAVariable, value: BitVecRef):
        raise NotImplementedError

    def get_ssa_memory_at(self, location: BitVecRef, ssa_index: BitVecRef):
        raise NotImplementedError


class BacktrackingState(State):
    """
    Backtracking state that can look up requested variables via the SSA variable definitions.
    """

    def __init__(self, bv: BinaryView, function: Function, depth: int):
        super().__init__(bv, function)
        # TODO: Make variables an object that errors upon assigning the same value twice?
        # NOTE: This variables object is shared by all states that are copies of this one.
        self.variables = {}
        self.depth = depth
        # This might not be needed. The variables object may be useable... (oldest variable in it...?)
        # NOTE: This potential_inputs object is shared by all states that are copies of this one.
        self.potential_inputs = []

    def get_ssa_variable(self, variable: SSAVariable):
        """
        Look up SSA variable by executing the instruction in which it was defined

        :variable: SSAVariable to look up.
        """
        definition_instruction = self.function.mlil.ssa_form.get_ssa_var_definition(
            variable
        )
        result = None
        if definition_instruction and self.depth > 0:
            MLILInstructionExecutor(self.bv, definition_instruction).execute(
                self.next_state()
            )
            result = self.variables[variable]
        else:
            name = repr(variable)
            size = variable.var.type.width * 8
            result = BitVec(name, size)
            self.potential_inputs.append(result)

        self.variables[variable] = result
        return result

    def get_unconstrained_variable(self, name: str, size_bytes: int):
        """
        Return an unconstrained BitVec

        :name: Name of the bitvector
        :size_bytes: Size of the bitvector in bytes
        """
        size = size_bytes * 8
        result = BitVec(name, size)
        self.potential_inputs.append(result)

        return result

    def set_ssa_variable(self, variable: SSAVariable, value: BitVecRef):
        """
        Set a SSA variable to a value

        :variable: Variable to set
        :value: Value to set the variable to
        """
        self.variables[variable] = value

    def get_ssa_memory_at(self, location: BitVecRef, ssa_index: BitVecRef):
        """
        Read ssa memory. Currently only returns a bitvec.

        :location: Location to read memory from
        :ssa_index: SSA memory index
        """
        # TODO: This can be much more better.
        name = repr(location)
        size = self.bv.arch.address_size * 8
        result = BitVec(name, size)
        self.potential_inputs.append(result)
        return result

    def next_state(self):
        """
        Get the next state for a newly executed instruction
        """

        state = BacktrackingState(self.bv, self.function, self.depth - 1)
        state.variables = self.variables
        state.potential_inputs = self.potential_inputs
        return state
