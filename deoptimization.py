from .integer_division_binary_search import integer_division_binary_search
from .modulo_binary_search import modulo_binary_search
from .modulo_binary_search import modulo_binary_search
from .state import BacktrackingState
from .instructions import MLILInstructionExecutor
from z3 import Solver, simplify, sat
from binaryninja import (
    MediumLevelILOperation,
    BackgroundTaskThread,
    log,
    BinaryView,
    MediumLevelILInstruction,
    Function,
)


def annotate_operations_ending_at_mlil_instruction(
    bv: BinaryView, instruction: MediumLevelILInstruction, function: Function
):
    """
    Annotate divisions and modulos that end at the specified MLIL instruction

    :bv: Current binaryview
    :instruction: Instruction to examine
    :function: Current function
    """
    ssa_instruction = instruction.ssa_form

    # TODO: There is probably an easy way to know more instructions that can be skipped.

    if ssa_instruction.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
        log.log_debug("Deoptimizer: Skipping Instruction")
        return None

    # 15 found experimentially. There may be longer modulo optimiztions.
    backtracking_state = BacktrackingState(bv, function, depth=15)
    start = MLILInstructionExecutor(bv, ssa_instruction)

    try:
        start.execute(backtracking_state)
    except NotImplementedError as e:
        log.log_debug(
            "Unsupported Instruction: {}. If this instruction is necessary to deoptimize your code, please report this to the github: https://github.com/jmprdi/binja-division-deoptimization".format(
                e.args[0]
            )
        )
        return
    except Exception as e:
        log.log_warn(
            "Deoptimizer Error: {} Please report this to the github: https://github.com/jmprdi/binja-division-deoptimization".format(
                repr(e)
            )
        )
        raise e
        return

    if len(backtracking_state.potential_inputs) == 0:
        log.log_debug("Deoptimizer: No potential inputs")
        return None

    input_bv = backtracking_state.potential_inputs[-1]
    output_bv = backtracking_state.variables[ssa_instruction.dest]

    def do_operation(dividend):
        s = Solver()
        s.set("timeout", 10)
        s.add(input_bv == dividend)
        r = s.check()
        if r != sat:
            return None
        m = s.model()
        solved = m.eval(output_bv)
        try:
            return solved.as_long()
        except AttributeError:
            return None

    modulo = modulo_binary_search(do_operation, 2 ** input_bv.size())
    if modulo is not None:
        bv.set_comment_at(ssa_instruction.address, "modulo by {}".format(modulo))
        return

    divisor = integer_division_binary_search(do_operation, 2 ** input_bv.size())
    if divisor is not None:
        bv.set_comment_at(ssa_instruction.address, "divide by {}".format(divisor))
        return


class AnnotateAtMLILInstruction(BackgroundTaskThread):
    """
    Thread to annotate divisions and modulos that end at the specified MLIL instruction
    """

    def __init__(
        self, bv: BinaryView, instruction: MediumLevelILInstruction, function: Function
    ):
        BackgroundTaskThread.__init__(
            self, "Deoptmizing Operations - Instruction", True
        )
        self.bv = bv
        self.instruction = instruction
        self.function = function

    def run(self):
        annotate_operations_ending_at_mlil_instruction(
            self.bv, self.instruction, self.function
        )


class AnnotateAtFunction(BackgroundTaskThread):
    """
    Thread to annotate divisions and modulos on every line in a function.
    """

    def __init__(self, bv: BinaryView, function: Function):
        BackgroundTaskThread.__init__(self, "Deoptimizing Operations - Function", True)
        self.bv = bv
        self.function = function

    def run(self):
        for bb in self.function.mlil_basic_blocks:
            for instruction in bb:
                annotate_operations_ending_at_mlil_instruction(
                    self.bv, instruction, self.function
                )


def annotate_operations_ending_at_address(bv: BinaryView, address: int):
    """
    Plugin command to annotate divisions and modulos that end at an address.

    :bv: Current binaryview
    :address: Address to check
    """
    function = bv.get_functions_containing(address)[0]
    instruction = function.get_low_level_il_at(address).mlil

    t = AnnotateAtMLILInstruction(bv, instruction, function)
    t.start()


def annotate_operations_in_function(bv: BinaryView, function: Function):
    """
    Plugin command to annotate divisions and modulos on every line in a function.

    :bv: Current binaryview
    :function: Function to check
    """
    t = AnnotateAtFunction(bv, function)
    t.start()
