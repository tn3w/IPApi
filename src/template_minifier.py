#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTML Template Minifier for IPApi.

This module handles the minification of HTML templates in the templates directory,
with special handling for inline CSS and JavaScript.
"""

import os
import re
import glob
from typing import Dict, Tuple, List

import htmlmin  # type: ignore
from csscompressor import compress as compress_css  # type: ignore
from jsmin import jsmin  # type: ignore


def extract_inline_styles(html_content: str) -> Tuple[str, List[str]]:
    """
    Extract inline <style> tags from HTML content.

    Args:
        html_content: HTML content to extract from

    Returns:
        Tuple of HTML with placeholders and list of extracted styles
    """
    style_pattern = re.compile(r"<style>(.*?)</style>", re.DOTALL)
    styles = style_pattern.findall(html_content)

    modified_html = html_content
    for i, style in enumerate(styles):
        placeholder = f"<!-- STYLE_PLACEHOLDER_{i} -->"
        modified_html = modified_html.replace(
            f"<style>{style}</style>", f"<style>{placeholder}</style>"
        )

    return modified_html, styles


def extract_inline_scripts(html_content: str) -> Tuple[str, List[str]]:
    """
    Extract inline <script> tags (without src attribute) from HTML content.

    Args:
        html_content: HTML content to extract from

    Returns:
        Tuple of HTML with placeholders and list of extracted scripts
    """
    script_pattern = re.compile(r"<script(?!\s+src=)(.*?)>(.*?)</script>", re.DOTALL)
    matches = script_pattern.findall(html_content)

    scripts: List[str] = []
    modified_html = html_content

    for i, match in enumerate(matches):
        attrs, content = match
        if content.strip():
            placeholder = f"<!-- SCRIPT_PLACEHOLDER_{i} -->"
            scripts.append(content)
            original_script = f"<script{attrs}>{content}</script>"
            replacement = f"<script{attrs}>{placeholder}</script>"
            modified_html = modified_html.replace(original_script, replacement)

    return modified_html, scripts


def reinsert_content(html_content: str, styles: List[str], scripts: List[str]) -> str:
    """
    Reinsert minified inline styles and scripts back into HTML content.

    Args:
        html_content: HTML content with placeholders
        styles: List of minified styles
        scripts: List of minified scripts

    Returns:
        HTML with placeholders replaced with minified content
    """
    result = html_content

    for i, style in enumerate(styles):
        placeholder = f"<!-- STYLE_PLACEHOLDER_{i} -->"
        result = result.replace(placeholder, style)

    for i, script in enumerate(scripts):
        placeholder = f"<!-- SCRIPT_PLACEHOLDER_{i} -->"
        result = result.replace(placeholder, script)

    return result


def minify_html_file(file_path: str) -> str:
    """
    Minify an HTML file with special handling for inline CSS and JS.

    Args:
        file_path: Path to HTML file

    Returns:
        Minified HTML content
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    content_with_style_placeholders, styles = extract_inline_styles(content)
    content_with_placeholders, scripts = extract_inline_scripts(
        content_with_style_placeholders
    )

    minified_html = htmlmin.minify(  # type: ignore
        content_with_placeholders,
        remove_comments=False,
        remove_empty_space=True,
        reduce_boolean_attributes=True,
    )

    minified_styles = [compress_css(style) for style in styles]
    minified_scripts = [jsmin(script).replace("\n", "") for script in scripts]

    result = reinsert_content(minified_html, minified_styles, minified_scripts)

    final_result = htmlmin.minify(  # type: ignore
        result,
        remove_comments=True,
        remove_empty_space=True,
        reduce_boolean_attributes=True,
    )

    return final_result


def minify_templates(templates_dir: str = "templates") -> Dict[str, Tuple[int, int]]:
    """
    Minify all HTML files in the templates directory.

    Args:
        templates_dir: Path to templates directory

    Returns:
        Dictionary of file paths and their original/minified sizes
    """
    results_dict: Dict[str, Tuple[int, int]] = {}
    template_files = glob.glob(os.path.join(templates_dir, "*.html"))

    for file_path in template_files:
        with open(file_path, "r", encoding="utf-8") as f:
            original_content = f.read()
            original_size = len(original_content)

        minified_content = minify_html_file(file_path)
        minified_size = len(minified_content)

        minified_dir = os.path.join(templates_dir, "minified")
        os.makedirs(minified_dir, exist_ok=True)

        minified_filename = os.path.basename(file_path)
        minified_path = os.path.join(minified_dir, minified_filename)

        with open(minified_path, "w", encoding="utf-8") as f:
            f.write(minified_content)

        results_dict[minified_filename] = (original_size, minified_size)

    return results_dict


if __name__ == "__main__":
    results = minify_templates()

    print("Template Minification Results:")
    print("-" * 60)
    print(f"{'Filename':<20} {'Original':<10} {'Minified':<10} {'Reduction':<10}")
    print("-" * 60)

    for filename, (original, minified) in results.items():
        reduction = ((original - minified) / original) * 100
        print(f"{filename:<20} {original:<10,d} {minified:<10,d} {reduction:.1f}%")
