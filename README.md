    # Browser Artifact Analyzer — Offline Digital Forensics Tool

    [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
    [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
    [![Offline](https://img.shields.io/badge/mode-offline%20first-important.svg)](#)
    [![secintel](https://img.shields.io/badge/schema-secintel%20v1-purple.svg)](https://github.com/reshot2005/secintel-core)
    [![GitHub](https://img.shields.io/badge/github-reshot2005%2Fbrowser-artifact-analyzer-black.svg)](https://github.com/reshot2005/browser-artifact-analyzer)

    > **Parse Chrome/Firefox history and cookies into searchable timelines — browser forensics for DFIR and insider investigations.**

    **Category:** Digital Forensics  
    **Collection phase tool:** 4/10  
    **Schema:** [secintel-core](https://github.com/reshot2005/secintel-core) v1  
    **Repository:** https://github.com/reshot2005/browser-artifact-analyzer  
    **Author account:** [reshot2005](https://github.com/reshot2005)

    ## Why Browser Artifact Analyzer ranks for security search

    Browser Artifact Analyzer is an **offline-first**, research-grade **digital forensics** utility designed for practitioners who need reproducible analysis without uploading sensitive artifacts to SaaS scanners. It emits structured findings through the shared **secintel** evidence taxonomy (OBSERVED / DERIVED / INFERRED / CORRELATED / VERIFIED) so results are auditable, exportable, and CI-friendly.

    ### Primary SEO keywords
    `browser forensics, Chrome history, Firefox cookies, web artifact analysis, DFIR browser`

    ### Topics
    `digital-forensics` `dfir` `incident-response` `cybersecurity` `forensics` `threat-hunting` `security-tools` `python` `offline-security` `blue-team` `browser-forensics` `chrome`

    ## What problem does this solve?

    Extract browser history/cookie artifacts into searchable investigative timelines for Chrome and Firefox.

    Focused browser artifact timeline tool.

    ## Key features

    - Chrome/Firefox artifact parsing
- History/cookie timelines
- Searchable investigative views
- Offline parsing
- Exportable findings

    ## Ideal use cases

    - Investigate user browsing
- Recover session artifacts
- Support insider cases

    ## Who should use this

    - Security engineers & AppSec / NetSec specialists
    - SOC / DFIR / malware analysts (as applicable)
    - Bug bounty hunters and penetration testers
    - DevSecOps teams needing offline/air-gapped tooling
    - Students and researchers learning digital forensics

    ## Quick start

    ```bash
    git clone https://github.com/reshot2005/browser-artifact-analyzer.git
    cd browser-artifact-analyzer
    python3.12 -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
    pip install -e ../secintel-core  # or: pip install -e git+https://github.com/reshot2005/secintel-core.git#egg=secintel-core
    pip install -e ".[dev]"

    browser-artifact-analyzer analyze sample_data --json
    browser-artifact-analyzer analyze sample_data --html report.html
    browser-artifact-analyzer version
    ```

    ### Exports for interoperability

    ```bash
    browser-artifact-analyzer analyze sample_data \
      --json --html report.html --csv findings.csv --sarif results.sarif
    ```

    ## Evidence quality & reproducibility

    - Findings follow **secintel** classification rules (confidence only where schema allows).
    - Provenance includes tool version, config hash, and input integrity metadata.
    - Set `SECINTEL_SOURCE_DATE_EPOCH` for deterministic timestamps in CI.

    ```bash
    export SECINTEL_SOURCE_DATE_EPOCH=1704067200
    browser-artifact-analyzer analyze sample_data --json
    ```

    ## Development

    ```bash
    ruff check src tests
    mypy src
    pytest
    ```

    ## Related tools in this collection

    Browse more offline security research tools by [reshot2005](https://github.com/reshot2005?tab=repositories): network security, web AppSec, DevSecOps, digital forensics, and static malware analysis — each in its own public repository with the same secintel reporting contract.

    ## License

    MIT — free for research, education, and commercial use with attribution preserved.

    ---

    ### Discoverability blurb (search engines & GitHub)

    **Browser Artifact Analyzer (browser-artifact-analyzer)** — Parse Chrome/Firefox history and cookies into searchable timelines — browser forensics for DFIR and insider investigations. Search terms: browser forensics, Chrome history, Firefox cookies, web artifact analysis, DFIR browser. Open-source, MIT-licensed, Python 3.12, offline cybersecurity tool by reshot2005.
