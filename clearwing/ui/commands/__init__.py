"""CLI subcommand modules."""

from . import (
    ci,
    config,
    doctor,
    graph,
    history,
    interactive,
    mcp,
    operate,
    parallel,
    report,
    scan,
    sessions,
    setup,
    sourcehunt,
    webui,
)

ALL_COMMANDS = [
    setup,
    doctor,
    scan,
    report,
    history,
    config,
    interactive,
    graph,
    sessions,
    ci,
    parallel,
    mcp,
    operate,
    webui,
    sourcehunt,
]
