import importlib.util
import sys
from pathlib import Path
import pytest
from helpers.utils import fetch_external_objects

@pytest.fixture(scope='session')
def feeds2stix_marking():
    return fetch_external_objects()