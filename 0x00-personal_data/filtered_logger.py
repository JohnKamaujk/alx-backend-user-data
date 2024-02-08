#!/usr/bin/env python3
"""A module for filtering logs.
"""
import re
from typing import List


def filter_datum(fields: List[str],
                 redaction: str, message: str, separator: str) -> str:
    """Filters a log line."""
    pattern_extract = r'(?P<field>{})=[^{}]*'.format('|'.join(fields),
                                                     separator)
    pattern_replace = r'\g<field>={}'.format(redaction)
    return re.sub(pattern_extract, pattern_replace, message)
