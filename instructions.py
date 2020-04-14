from binaryninja import log

from z3 import LShR, ZeroExt, SignExt, BitVec, BitVecVal, Extract

class MLILInstructionExecutor:
    def __init__(self, instruction):
        self.instruction = instruction

    def execute(self, state):
        operation = self.instruction.operation.name
        log.log_debug("Evaluating {}: {}".format(operation, self.instruction))

        try:
            if self.instruction.value.is_constant:
                log.log_debug("{} simplified to {}".format(self.instruction, self.instruction.value.value))
                size = self.instruction.size * 8
                return BitVecVal(self.instruction.value.value, size)
        except AttributeError:
            pass

        executor = getattr(self, 'evaluate_' + operation, None)

        if executor is not None:
            return executor(state)
        else:
            raise NotImplementedError("UNSUPPORTED OPERATION: {}".format(operation))

    def evaluate_MLIL_ADD(self, state):
        instruction_1, instruction_2 = self.instruction.operands
        operand_1 = MLILInstructionExecutor(instruction_1).execute(state)
        operand_2 = MLILInstructionExecutor(instruction_2).execute(state)
        return operand_1 + operand_2

    def evaluate_MLIL_ASR(self, state):
        instruction_1, instruction_2 = self.instruction.operands
        operand_1 = MLILInstructionExecutor(instruction_1).execute(state)
        operand_2 = MLILInstructionExecutor(instruction_2).execute(state)
        return operand_1 >> operand_2

    def evaluate_MLIL_LSR(self, state):
        instruction_1, instruction_2 = self.instruction.operands
        operand_1 = MLILInstructionExecutor(instruction_1).execute(state)
        operand_2 = MLILInstructionExecutor(instruction_2).execute(state)
        return LShR(operand_1, operand_2)

    def evaluate_MLIL_MUL(self, state):
        instruction_1, instruction_2 = self.instruction.operands
        operand_1 = MLILInstructionExecutor(instruction_1).execute(state)
        operand_2 = MLILInstructionExecutor(instruction_2).execute(state)
        return operand_1 * operand_2

    def evaluate_MLIL_SET_VAR_SSA(self, state):
        ssa_variable, next_instruction = self.instruction.operands
        value = MLILInstructionExecutor(next_instruction).execute(state)
        state.set_ssa_variable(ssa_variable, value)

    def evaluate_MLIL_SUB(self, state):
        instruction_1, instruction_2 = self.instruction.operands
        operand_1 = MLILInstructionExecutor(instruction_1).execute(state)
        operand_2 = MLILInstructionExecutor(instruction_2).execute(state)
        return operand_1 - operand_2

    def evaluate_MLIL_SX(self, state):
        # TODO: Confirm size
        (instruction,) = self.instruction.operands
        operand = MLILInstructionExecutor(instruction).execute(state)
        return SignExt(32, operand)

    def evaluate_MLIL_VAR_ALIASED(self, state):
        # TODO: Figure out if there is a more correct way to execute this
        (ssa_variable,) = self.instruction.operands
        return state.get_ssa_variable(ssa_variable)

    def evaluate_MLIL_VAR_SSA(self, state):
        (ssa_variable,) = self.instruction.operands
        return state.get_ssa_variable(ssa_variable)

    def evaluate_MLIL_VAR_SSA_FIELD(self, state):
        (ssa_variable, offset) = self.instruction.operands
        var = state.get_ssa_variable(ssa_variable)
        return Extract(31, offset, var)

    def evaluate_MLIL_ZX(self, state):
        # TODO: Confirm size
        (instruction,) = self.instruction.operands
        operand = MLILInstructionExecutor(instruction).execute(state)
        return ZeroExt(32, operand)
