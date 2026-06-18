"""Pytest configuration.

1. Makes the ``eventhorizon`` package importable without installation.
2. Provides a tiny, dependency-free runner for ``async def`` tests marked with
   ``@pytest.mark.asyncio`` so the suite runs WITHOUT the ``pytest-asyncio``
   third-party plugin. If ``pytest-asyncio`` *is* installed it takes precedence
   and this shim stays out of the way.
"""

import asyncio
import inspect
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def pytest_configure(config):
    # Register the marker so `-W error` / strict-markers doesn't warn.
    config.addinivalue_line(
        "markers", "asyncio: run an async test via the builtin stdlib shim"
    )


# Detect whether a real asyncio plugin is present; if so, defer to it.
def _real_asyncio_plugin_present() -> bool:
    try:
        import pytest_asyncio  # noqa: F401

        return True
    except Exception:
        return False


_HAS_PLUGIN = _real_asyncio_plugin_present()


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Execute ``async def`` test functions on a fresh event loop.

    Returning True tells pytest we handled the call. We only do this when the
    real pytest-asyncio plugin is absent, to avoid double-running.
    """
    if _HAS_PLUGIN:
        return None
    test_fn = pyfuncitem.obj
    if not inspect.iscoroutinefunction(test_fn):
        return None
    # Pass only the fixture args the test actually declares.
    funcargs = pyfuncitem.funcargs
    sig = inspect.signature(test_fn)
    kwargs = {name: funcargs[name] for name in sig.parameters if name in funcargs}
    asyncio.run(test_fn(**kwargs))
    return True
