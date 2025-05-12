<p align="center">
	<a href="https://github.com/tn3w/IPApi">
		<picture>
			<source width="800px" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/IPApi/releases/download/img/ipapi-dark.webp">
			<source width="800px" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/IPApi/releases/download/img/ipapi-light.webp">
			<img width="800px" alt="IPApi Screenshot" src="https://github.com/tn3w/IPApi/releases/download/img/ipapi-dark.webp">
		</picture>
	</a>
</p>

<h1 align="center">IPApi</h1>
<p align="center">A fast, efficient, and free Python-powered API for retrieving IP address information. </p>

## Installation and Usage

### Prerequisites

- Python 3.6 or higher
- Git

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/tn3w/IPApi.git
    cd IPApi
    ```

2. Create/activate an virtual environment:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Run the application:

    ```bash
    python3 app.py
    ```

## Todo

- [ ] Implement multiple ASN data sources for IP addresses like 2.2.2.2 that lack network information (improve coverage and reliability)
- [x] Add proper spacing and formatting to the location marker popup content on the map to improve readability

## License

Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
