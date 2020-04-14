from binaryninja import SSAVariable
from z3 import BitVecRef, BitVec
from copy import copy
from .instructions import MLILInstructionExecutor


class State:
    def __init__(self, function):
        self.function = function

    def get_ssa_variable(self, variable: SSAVariable):
        raise NotImplementedError

    def set_ssa_variable(self, variable: SSAVariable, value: BitVecRef):
        raise NotImplementedError


class BacktrackingState(State):
    def __init__(self, function, depth):
        super().__init__(function)
        # TODO: Make variables an object that errors upon assigning the same value twice?
        # NOTE: This variables object is shared by all states that are copies of this one.
        self.variables = {}
        self.depth = depth
        # THIS SHOULDNT BE NEEDED, variables should like only have one thing at the end
        # NOTE: This potential_inputs object is shared by all states that are copies of this one.
        self.potential_inputs = []

    def get_ssa_variable(self, variable: SSAVariable):
        existing_value = self.variables.get(variable, None)
        if existing_value is not None:
            return existing_value

        definition_instruction = self.function.mlil.ssa_form.get_ssa_var_definition(
            variable
        )
        result = None
        if definition_instruction and self.depth > 0:
            MLILInstructionExecutor(definition_instruction).execute(self.next_state())
            result = self.variables[variable]
        else:
            name = repr(variable)
            size = variable.var.type.width * 8
            result = BitVec(name, size)
            self.potential_inputs.append(result)

        self.variables[variable] = result
        return result

    def set_ssa_variable(self, variable: SSAVariable, value: BitVecRef):
        self.variables[variable] = value

    def next_state(self):
        state = BacktrackingState(self.function, self.depth - 1)
        state.variables = self.variables
        state.potential_inputs = self.potential_inputs
        return state
