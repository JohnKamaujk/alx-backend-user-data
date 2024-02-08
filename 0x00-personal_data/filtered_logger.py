#!/usr/bin/env python3
"""A module for filtering logs.
"""
import logging
import re
from typing import List


def filter_datum(fields: List[str],
                 redaction: str, message: str, separator: str) -> str:
    """Filters a log line."""
    pattern_extract = r'(?P<field>{})=[^{}]*'.format('|'.join(fields),
                                                     separator)
    pattern_replace = r'\g<field>={}'.format(redaction)
    return re.sub(pattern_extract, pattern_replace, message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a single record"""
        message = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields, self.REDACTION,
                            message, self.SEPARATOR)
