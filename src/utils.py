#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility functions for general application operations.

This module provides helper functions for common operations used across
the application, such as file downloading and error handling for network operations.
"""

import os
import urllib.request
import urllib.error


def download_file(url: str, output_path: str, name: str) -> None:
    """Download a file from a URL to a local path.

    Args:
        url (str): The URL of the file to download.
        output_path (str): The path to save the file to.
        name (str): The name of the file to download.
    """
    if os.path.exists(output_path):
        return

    directory_path = os.path.dirname(output_path)
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    try:
        print(f"Downloading {name} from {url}...")
        urllib.request.urlretrieve(url, output_path)
        print(f"Successfully downloaded {name} to {output_path}")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"Error downloading {name}: {e}")
