"""Attack harness for the lab: run the planted-weakness attacks and record findings.

Detectors are pure functions (see detectors.py) so the offline tests exercise them
without a model. The runner (runner.py) sends each case to the configured model and
writes findings for the report. Live runs use a real model (Ollama); the tests do not.
"""
