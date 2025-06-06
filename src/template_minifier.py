#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTML Template Minifier for IPApi.

This module handles the minification of HTML templates in the templates directory,
with special handling for inline CSS and JavaScript and external file references.
"""

import os
import re
import glob
from typing import Dict, Tuple, List, Optional

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


def extract_external_scripts(
    html_content: str, base_path: str
) -> Tuple[str, Dict[str, str], Dict[str, str]]:
    """
    Extract and process external script references.

    Args:
        html_content: HTML content to process
        base_path: Base path for resolving relative file paths

    Returns:
        Tuple of HTML with placeholders, dict of script paths and their content,
        and dict mapping placeholders to original tags
    """
    script_pattern = re.compile(
        r'<script\s+src=["\']([^"\']+)["\'][^>]*></script>', re.DOTALL
    )
    matches = script_pattern.findall(html_content)

    scripts: Dict[str, str] = {}
    placeholders: Dict[str, str] = {}
    modified_html = html_content

    for src in matches:
        try:
            if src.startswith(("http:", "https:")):
                continue

            script_path = os.path.join(base_path, src)

            if os.path.exists(script_path):
                with open(script_path, "r", encoding="utf-8") as f:
                    script_content = f.read()
                    scripts[src] = script_content

                placeholder = f"<!-- EXTERNAL_SCRIPT_PLACEHOLDER_{src} -->"
                original_tag = f'<script src="{src}"></script>'
                placeholders[placeholder] = original_tag
                modified_html = modified_html.replace(original_tag, placeholder)
        except Exception as e:
            print(f"Error processing script {src}: {e}")

    return modified_html, scripts, placeholders


def extract_external_styles(
    html_content: str, base_path: str
) -> Tuple[str, Dict[str, str], Dict[str, str]]:
    """
    Extract and process external stylesheet references.

    Args:
        html_content: HTML content to process
        base_path: Base path for resolving relative file paths

    Returns:
        Tuple of HTML with placeholders, dict of style paths and their content,
        and dict mapping placeholders to original tags
    """
    link_pattern = re.compile(
        r'<link\s+[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>',
        re.DOTALL,
    )
    link_pattern_alt = re.compile(
        r'<link\s+[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>',
        re.DOTALL,
    )

    matches = link_pattern.findall(html_content) + link_pattern_alt.findall(
        html_content
    )

    styles: Dict[str, str] = {}
    placeholders: Dict[str, str] = {}
    modified_html = html_content

    for href in matches:
        try:
            if href.startswith(("http:", "https:")):
                continue

            style_path = os.path.join(base_path, href)

            if os.path.exists(style_path):
                with open(style_path, "r", encoding="utf-8") as f:
                    style_content = f.read()
                    styles[href] = style_content

                placeholder = f"<!-- EXTERNAL_STYLE_PLACEHOLDER_{href} -->"

                pattern1 = f'<link\\s+href="{href}"\\s+rel="stylesheet"[^>]*>'
                pattern2 = f'<link\\s+rel="stylesheet"\\s+href="{href}"[^>]*>'

                link_tags = re.findall(pattern1, html_content) + re.findall(
                    pattern2, html_content
                )

                for tag in link_tags:
                    placeholders[placeholder] = tag
                    modified_html = modified_html.replace(tag, placeholder)
        except Exception as e:
            print(f"Error processing stylesheet {href}: {e}")

    return modified_html, styles, placeholders


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


def inline_external_resources(
    html_content: str,
    external_scripts: Dict[str, str],
    external_styles: Dict[str, str],
    script_placeholders: Dict[str, str],
    style_placeholders: Dict[str, str],
) -> str:
    """
    Replace external resource references with inlined minified content.

    Args:
        html_content: HTML content with placeholders
        external_scripts: Dict of script paths and their minified content
        external_styles: Dict of style paths and their minified content
        script_placeholders: Dict mapping placeholders to original script tags
        style_placeholders: Dict mapping placeholders to original style tags

    Returns:
        HTML with external resources inlined
    """
    result = html_content

    for src, content in external_scripts.items():
        placeholder = f"<!-- EXTERNAL_SCRIPT_PLACEHOLDER_{src} -->"
        if placeholder in result:
            result = result.replace(placeholder, f"<script>{content}</script>")

    for href, content in external_styles.items():
        placeholder = f"<!-- EXTERNAL_STYLE_PLACEHOLDER_{href} -->"
        if placeholder in result:
            result = result.replace(placeholder, f"<style>{content}</style>")

    return result


def minify_html_file(file_path: str, output_dir: Optional[str] = None) -> str:
    """
    Minify an HTML file with special handling for inline CSS and JS.

    Args:
        file_path: Path to HTML file
        output_dir: Output directory for minified HTML

    Returns:
        Minified HTML content
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    base_path = os.path.dirname(file_path)
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(file_path), "minified")

    content_with_style_placeholders, styles = extract_inline_styles(content)
    content_with_script_placeholders, scripts = extract_inline_scripts(
        content_with_style_placeholders
    )

    content_with_external_script_placeholders, external_scripts, script_placeholders = (
        extract_external_scripts(content_with_script_placeholders, base_path)
    )
    content_with_all_placeholders, external_styles, style_placeholders = (
        extract_external_styles(content_with_external_script_placeholders, base_path)
    )

    minified_html = htmlmin.minify(  # type: ignore
        content_with_all_placeholders,
        remove_comments=False,
        remove_empty_space=True,
        reduce_boolean_attributes=True,
    )

    minified_styles = [compress_css(style) for style in styles]
    minified_scripts = [jsmin(script).replace("\n", "") for script in scripts]

    minified_external_scripts = {
        src: jsmin(script).replace("\n", "") for src, script in external_scripts.items()
    }
    minified_external_styles = {
        href: compress_css(style) for href, style in external_styles.items()
    }

    result_with_inline = reinsert_content(
        minified_html, minified_styles, minified_scripts
    )

    result_with_all = inline_external_resources(
        result_with_inline,
        minified_external_scripts,
        minified_external_styles,
        script_placeholders,
        style_placeholders,
    )

    final_result = htmlmin.minify(  # type: ignore
        result_with_all,
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

    minified_dir = os.path.join(templates_dir, "minified")
    os.makedirs(minified_dir, exist_ok=True)

    for file_path in template_files:
        with open(file_path, "r", encoding="utf-8") as f:
            original_content = f.read()
            original_size = len(original_content)

        minified_content = minify_html_file(file_path, minified_dir)
        minified_size = len(minified_content)

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
