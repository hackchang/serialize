# -*- coding: utf-8 -*-
"""
    serialize.testsuite.test_security
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Regression tests for the CWE-502 hardening: code-executing formats
    (pickle, dill) must never be auto-selected from a file extension. A caller
    that only intends to read data (``serialize.load(path)``) must not be
    silently routed to a code-executing deserializer just because of the file
    name/extension; using such a format requires an explicit ``fmt=``.
"""

import pickle

import pytest

import serialize
from serialize.all import UNSAFE_FORMATS


def test_pickle_and_dill_are_marked_unsafe():
    assert "pickle" in UNSAFE_FORMATS
    # dill is optional; only assert when it is available
    from serialize.all import FORMATS

    if "dill" in FORMATS:
        assert "dill" in UNSAFE_FORMATS


def test_load_pickle_by_extension_is_refused(tmp_path):
    p = tmp_path / "data.pickle"
    p.write_bytes(pickle.dumps({"answer": 42}))

    # auto-detection by extension must refuse the code-executing pickle backend
    with pytest.raises(ValueError):
        serialize.load(str(p))

    # ... but an explicit opt-in still works
    assert serialize.load(str(p), fmt="pickle") == {"answer": 42}


def test_dump_pickle_by_extension_is_refused(tmp_path):
    p = tmp_path / "data.pickle"

    with pytest.raises(ValueError):
        serialize.dump({"answer": 42}, str(p))

    serialize.dump({"answer": 42}, str(p), fmt="pickle")
    assert serialize.load(str(p), fmt="pickle") == {"answer": 42}


def test_dill_by_extension_is_refused(tmp_path):
    dill = pytest.importorskip("dill")
    p = tmp_path / "data.dill"
    p.write_bytes(dill.dumps({"answer": 42}))

    with pytest.raises(ValueError):
        serialize.load(str(p))

    assert serialize.load(str(p), fmt="dill") == {"answer": 42}


def test_safe_formats_are_still_autodetected(tmp_path):
    # a data-only format must keep working without an explicit fmt
    p = tmp_path / "data.json"
    serialize.dump({"answer": 42}, str(p))
    assert serialize.load(str(p)) == {"answer": 42}
