"""Scanners return a dict with `reachable`, `items` and `findings`.

An item describes one cryptographic algorithm in use:
    algorithm, primitive (CycloneDX enum), role (kex|auth|cipher|code),
    quantum (vulnerable|weakened|safe), nist_level, param, location, line
A finding is a message for the operator: severity (critical|warning|info), text.
"""
