"""A Markdown summary of a findings.json, for GitHub's job summary page (`securegate summary`).

It is the same report as the pull request comment, without the hidden marker; see
securegate.outputs.markdown. It reads the report through the dashboard's loader, which refuses
any report holding a value that is not masked, so a summary can only ever hold masked values.
"""

from securegate.outputs.markdown import render_summary

__all__ = ["render_summary"]
