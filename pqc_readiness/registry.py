"""Registries that let a module add CLI flags and output formats without
editing shared code (#80, roadmap #137).

* ``register_arguments(order)`` decorates a module's ``add_arguments(parser)``
  hook.  ``cli.build_parser()`` calls every hook sorted by ``order``, so a
  module's flags appear in ``--help`` at a stable position without anyone
  editing the parser.  Current slots (leave gaps for new modules):

      10-19  output format flags (--json, --markdown, --cbom, --spdx, --sarif)
      20     benchmarks              30-31  gates, --save / --output
      40     --quiet / --no-color    50-51  trust store, packages
      60     --host-mount            70     --ansible
      80     recommendation          90     aggregation
      100    --debug / --version

* ``register_output(OutputFormat(...))`` declares a report format selected by
  a boolean flag.  When several format flags are set, the lowest
  ``precedence`` wins; with none set the plain-text report is emitted.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .report import Report

ArgumentHook = Callable[[argparse.ArgumentParser], None]

_ARGUMENT_HOOKS: list[tuple[int, str, ArgumentHook]] = []


def register_arguments(order: int) -> Callable[[ArgumentHook], ArgumentHook]:
    """Decorator: add ``hook(parser)`` to the CLI at position ``order``."""

    def deco(hook: ArgumentHook) -> ArgumentHook:
        key = f"{hook.__module__}.{hook.__qualname__}"
        if any(k == key for _, k, _ in _ARGUMENT_HOOKS):
            raise ValueError(f"argument hook registered twice: {key}")
        _ARGUMENT_HOOKS.append((order, key, hook))
        return hook

    return deco


def argument_hooks() -> list[ArgumentHook]:
    """Registered hooks in CLI order (ties broken by module name)."""
    return [hook for _, _, hook in sorted(_ARGUMENT_HOOKS, key=lambda h: (h[0], h[1]))]


@dataclass(frozen=True)
class OutputFormat:
    """A report format selected by the boolean CLI flag ``--<dest>``."""

    dest: str
    precedence: int
    render: Callable[[Report], str]
    # Machine-readable formats switch ANSI colour off.
    machine_readable: bool = True


_OUTPUTS: dict[str, OutputFormat] = {}


def register_output(fmt: OutputFormat) -> OutputFormat:
    if fmt.dest in _OUTPUTS:
        raise ValueError(f"output format registered twice: {fmt.dest}")
    _OUTPUTS[fmt.dest] = fmt
    return fmt


def outputs() -> list[OutputFormat]:
    """Registered formats, highest precedence (lowest number) first."""
    return sorted(_OUTPUTS.values(), key=lambda f: f.precedence)

def positive_int(value: str) -> int:
    """argparse ``type=`` for flags that must be >= 1."""
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from None
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {n}")
    return n
