from .integer_division_binary_search import integer_division_binary_search
from .modulo_binary_search import modulo_binary_search
from .state import BacktrackingState
from .instructions import MLILInstructionExecutor
from z3 import Solver, simplify, sat
from binaryninja import MediumLevelILOperation, BackgroundTaskThread, log


def annotate_division_ending_at_mlil_instruction(bv, instruction, function):
    ssa_instruction = instruction.ssa_form

    # TODO: There is probably an easy way to know more instructions that can be skipped.

    if ssa_instruction.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
        log.log_debug("Deoptimizer: Skipping Instruction")
        return None

    backtracking_state = BacktrackingState(bv, function, depth=7)
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

    def do_divide(dividend):
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

    divisor = integer_division_binary_search(do_divide, 2 ** input_bv.size())
    if divisor is not None:
        bv.set_comment_at(ssa_instruction.address, "divide by {}".format(divisor))


class AnnotateAtMLILInstruction(BackgroundTaskThread):
    def __init__(self, bv, instruction, function):
        BackgroundTaskThread.__init__(self, "Deoptmizing Division - Instruction", True)
        self.bv = bv
        self.instruction = instruction
        self.function = function

    def run(self):
        annotate_division_ending_at_mlil_instruction(
            self.bv, self.instruction, self.function
        )


class AnnotateAtFunction(BackgroundTaskThread):
    def __init__(self, bv, function):
        BackgroundTaskThread.__init__(self, "Deoptimizing Division - Function", True)
        self.bv = bv
        self.function = function

    def run(self):
        for bb in self.function.mlil_basic_blocks:
            for instruction in bb:
                annotate_division_ending_at_mlil_instruction(
                    self.bv, instruction, self.function
                )


def annotate_division_ending_at_address(bv, address):
    function = bv.get_functions_containing(address)[0]
    instruction = function.get_low_level_il_at(address).mlil

    t = AnnotateAtMLILInstruction(bv, instruction, function)
    t.start()


def annotate_divisions_in_function(bv, function):
    t = AnnotateAtFunction(bv, function)
    t.start()
