from binaryninja.plugin import PluginCommand
from binaryninja.interaction import get_choice_input, show_message_box
from binaryninja import MessageBoxButtonSet, log

def register_commands():
    from .deoptimization import (
        annotate_operations_ending_at_address,
        annotate_operations_in_function,
    )

    PluginCommand.register_for_address(
        "Deoptimize Operations - Line",
        "Uses z3 to deoptimize divisions and modulos ending at the specified line.",
        action=annotate_operations_ending_at_address,
    )

    PluginCommand.register_for_function(
        "Deoptimize Operations - Function",
        "Uses z3 to deoptimize divisions and modulos through the current function.",
        action=annotate_operations_in_function,
    )

try:
    import z3
    register_commands()
except ImportError:
    choice = show_message_box("Binja Deoptimizer - Error", "z3-solver is not installed in your current environment and is required to run the deoptimization plugin. Please install z3-solver and restart binaryninja.", MessageBoxButtonSet.OKButtonSet)
    log.log_error("Binja Deoptimizer - z3-solver not installed, unable to run.")
