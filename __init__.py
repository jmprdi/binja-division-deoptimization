from .deoptimization import annotate_divisions_ssa

from binaryninja.plugin import PluginCommand


PluginCommand.register_for_range(
    "Deoptimize Division SSA",
    "Uses smarts to deoptimize division",
    action=annotate_divisions_ssa,
)
