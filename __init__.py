from .deoptimization_prev import annotate_divisions
from .deoptimization import annotate_divisions_ssa

from binaryninja.plugin import PluginCommand

PluginCommand.register_for_function(
    "Deoptimize Division Old - Func",
    "Uses smarts to deoptimize division",
    action=annotate_divisions,
)

PluginCommand.register_for_range(
    "Deoptimize Division SSA",
    "Uses smarts to deoptimize division",
    action=annotate_divisions_ssa,
)
