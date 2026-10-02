"""Vigil — find it before they do.

An offline scanner for the secrets that end up in text: a config file, a source
file, a .env, a log, a CI job. It names what it recognises, shows a redacted
preview rather than the value, grades the exposure, and says plainly what it
cannot know.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
