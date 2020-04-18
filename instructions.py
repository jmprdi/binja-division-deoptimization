from binaryninja import log

from z3 import LShR, ZeroExt, SignExt, BitVec, BitVecVal, Extract


class MLILInstructionExecutor:
    def __init__(self, bv, instruction):
        self.bv = bv
        self.instruction = instruction

    def instructions_to_operands(self, instructions, state, size):
        operands = []
        largest_size = size * 8
        for instruction in instructions:
            ops = MLILInstructionExecutor(self.bv, instruction).execute(state)
            # TODO: Should this be here?
            for op in ops:
                if op.size() > largest_size:
                    largest_size = op.size()
                operands.append(op)

        print(largest_size)
        print(operands)

        for i, op in enumerate(operands):
            if op.size() < largest_size:
                operands[i] = ZeroExt(largest_size - op.size(), op)

        print(operands)

        return operands

    def execute(self, state):
        operation = self.instruction.operation.name
        log.log_debug("Evaluating {}: {} @ {}".format(operation, self.instruction, hex(self.instruction.address)))

        try:
            if self.instruction.value.is_constant:
                log.log_debug(
                    "{} simplified to {}".format(
                        self.instruction, self.instruction.value.value
                    )
                )
                size = self.instruction.size * 8
                # FIXME: Constant size messes up extracts; signed operations / signextend / etc
                # FIXME: SIZES MUST BE CHECKED & UPDATED IN EACH OPERATION.
                return [BitVecVal(self.instruction.value.value, size)]
        except AttributeError:
            pass

        executor = getattr(self, "evaluate_" + operation, None)

        if executor is not None:
            result = executor(state)
        else:
            raise NotImplementedError("UNSUPPORTED OPERATION: {}".format(operation))

        for i in range(len(result)):
            width = self.instruction.size * 8
            if width < result[i].size():
                result[i] = Extract(width - 1, 0, result[i])
            if width > result[i].size():
                result[i] = ZeroExt(width - result[i].size(), result[i])

        log.log_debug("Completed {}: {} @ {}".format(operation, self.instruction, hex(self.instruction.address)))

        return result

    def evaluate_MLIL_ADD(self, state):
        operand_1, operand_2 = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)

        return [operand_1 + operand_2]

    def evaluate_MLIL_ASR(self, state):
        operand_1, operand_2 = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)

        return [operand_1 >> operand_2]

    def evaluate_MLIL_LSR(self, state):
        operand_1, operand_2 = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)

        return [LShR(operand_1, operand_2)]

    def evaluate_MLIL_LOAD_SSA(self, state):
        (instruction, ssa_number) = self.instruction.operands
        # memory_location_1 = MLILInstructionExecutor(self.bv, instruction_1).execute(state)
        return [state.get_ssa_memory_at(None, None)]

    def evaluate_MLIL_MUL(self, state):
        operand_1, operand_2 = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)

        return [operand_1 * operand_2]

    def evaluate_MLIL_MULS_DP(self, state):
        # TODO: CONFIRM THIS IS CORRECT
        operand_1, operand_2 = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)

        result_size = self.instruction.size * 8 * 2

        result = SignExt(result_size // 2, operand_1) * SignExt(result_size // 2, operand_2)
        result_1 = Extract(result_size - 1, result_size // 2, result)
        result_2 = Extract(result_size // 2 - 1, 0, result)

        print(result_1.size())
        print(result_2.size())

        return [result_1, result_2]

    def evaluate_MLIL_SET_VAR_SSA(self, state):
        (ssa_variable, next_instruction) = self.instruction.operands
        [value] = self.instructions_to_operands([next_instruction], state, self.instruction.size)
        state.set_ssa_variable(ssa_variable, value)

        return []

    def evaluate_MLIL_SET_VAR_SPLIT_SSA(self, state):
        (ssa_variable_1, ssa_variable_2, next_instruction) = self.instruction.operands
        [value1, value2] = self.instructions_to_operands([next_instruction], state, self.instruction.size)
        state.set_ssa_variable(ssa_variable_1, value1)
        state.set_ssa_variable(ssa_variable_2, value2)

        return []

    def evaluate_MLIL_SUB(self, state):
        operand_1, operand_2 = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)
        return [operand_1 - operand_2]

    def evaluate_MLIL_SX(self, state):
        # TODO: Confirm size
        [operand] = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)
        return [SignExt(32, operand)]

    def evaluate_MLIL_VAR_ALIASED(self, state):
        # TODO: Figure out if there is a more correct way to execute this
        (ssa_variable,) = self.instruction.operands
        return [state.get_ssa_variable(ssa_variable)]

    def evaluate_MLIL_VAR_SSA(self, state):
        (ssa_variable,) = self.instruction.operands
        return [state.get_ssa_variable(ssa_variable)]

    def evaluate_MLIL_VAR_SSA_FIELD(self, state):
        (ssa_variable, offset) = self.instruction.operands
        var = state.get_ssa_variable(ssa_variable)
        return [Extract(31, offset, var)]

    def evaluate_MLIL_ZX(self, state):
        # TODO: Confirm size
        [operand] = self.instructions_to_operands(self.instruction.operands, state, self.instruction.size)
        return [ZeroExt(32, operand)]
