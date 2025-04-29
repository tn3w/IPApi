#!/usr/bin/env python3

"""
This script generates a mapping of ISO country codes to their corresponding currency codes.
The output is formatted as Rust code for use in src/geodata.rs.
"""

import urllib.request
import json


def main():
    """Main function to generate the currency mapping."""

    # Download the JSON file
    url = (
        "https://raw.githubusercontent.com/"
        "mluqmaan/world-countries-json/"
        "refs/heads/main/countries.json"
    )

    try:
        with urllib.request.urlopen(url) as response:
            data = response.read().decode("utf-8")

        # Parse the JSON data
        countries = json.loads(data)

        # Create the mapping
        currency_map = {}
        for country in countries:
            if (
                "isoAlpha2" in country
                and "currency" in country
                and "code" in country["currency"]
            ):
                currency_map[country["isoAlpha2"]] = country["currency"]["code"]

        # Format and print the mapping
        for iso, currency in currency_map.items():
            print(f'"{iso}" => "{currency}",')

    except urllib.error.URLError as e:
        print(f"Failed to download data: {e.reason}")


if __name__ == "__main__":
    main()
