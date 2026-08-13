"""Process-wide deny guards for required deterministic evaluation execution."""

from __future__ import annotations

import os
from contextlib import ExitStack
from types import TracebackType
from typing import Never
from unittest.mock import patch


class HermeticityError(RuntimeError):
    """A required evaluation attempted a network or process side effect."""


class HermeticExecutionGuard:
    """Deny network sockets, child processes, and ambient shell execution."""

    def __init__(self) -> None:
        self._stack = ExitStack()

    def __enter__(self) -> HermeticExecutionGuard:
        for target in (
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
            "os.system",
            "socket.create_connection",
            "socket.socket",
            "subprocess.Popen",
        ):
            self._stack.enter_context(patch(target, _deny_effect))
        for name in (
            "execl",
            "execle",
            "execlp",
            "execlpe",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "fork",
            "forkpty",
            "posix_spawn",
            "posix_spawnp",
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
        ):
            if hasattr(os, name):
                self._stack.enter_context(patch.object(os, name, _deny_effect))
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return self._stack.__exit__(exception_type, exception, traceback)


def _deny_effect(*_args: object, **_kwargs: object) -> Never:
    raise HermeticityError(
        "required deterministic evaluations deny network and process effects"
    )


__all__ = ["HermeticExecutionGuard", "HermeticityError"]
