#!/usr/bin/env python3
"""Authentication module for the API.
"""
from flask import request
from typing import List


class Auth:
    """Authentication class.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if path requires authentication.
        """
        return False

    def authorization_header(self, request=None) -> None:
        """Gets the authorization header field from the request.
        """
        return None

    def current_user(self, request=None) -> None:
        """Gets the current user from the request.
        """
        return None
