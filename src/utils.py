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
import tempfile
from typing import Union


def download_file(url: Union[str, list[str]], output_path: str, name: str) -> None:
    """Download a file from a URL to a local path.

    Args:
        url (Union[str, list[str]]): The URL of the file to download. Can be a single URL
            or a list of URLs. If a list is provided, all files will be downloaded and
            combined into a single output file.
        output_path (str): The path to save the file to.
        name (str): The name of the file to download.
    """
    if os.path.exists(output_path):
        return

    directory_path = os.path.dirname(output_path)
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    try:
        if isinstance(url, list):
            print(f"Downloading {name} from multiple URLs...")
            with open(output_path, "wb") as outfile:
                for single_url in url:
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_path = temp_file.name

                    try:
                        print(f"Downloading part from {single_url}...")
                        urllib.request.urlretrieve(single_url, temp_path)

                        with open(temp_path, "rb") as infile:
                            outfile.write(infile.read())

                        os.remove(temp_path)
                    except (
                        urllib.error.URLError,
                        urllib.error.HTTPError,
                        OSError,
                    ) as e:
                        print(f"Error downloading from {single_url}: {e}")
            print(f"Successfully downloaded {name} to {output_path}")
        else:
            print(f"Downloading {name} from {url}...")
            urllib.request.urlretrieve(url, output_path)
            print(f"Successfully downloaded {name} to {output_path}")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"Error downloading {name}: {e}")
