# MemTriage

MemTriage is a Python command-line triage wrapper for [Volatility 3](https://github.com/volatilityfoundation/volatility3). It collects selected Windows memory artifacts, groups them by process, applies explainable heuristics, and produces a ranked text report with optional JSON findings. It is intended to help an analyst decide what to inspect next; a score is not a malware verdict.

## What it examines

It calls `windows.pslist`, `windows.psscan`, `windows.cmdline`, `windows.malfind`, `windows.ldrmodules`, `windows.netscan`, and `windows.dlllist`. Findings include pool-scan-only process candidates, suspicious memory regions, PEB module-list discrepancies, command patterns, DLL locations, executable path *candidates* from loader metadata, and established remote connection artifacts. The report includes source plugin and row references, process times and offsets when available, and plugin errors or partial coverage.

Memory scans can contain exited processes and stale artifacts. Loader paths can be modified, and a network object is not proof of malicious activity. Confirm any finding with the original memory evidence and other case data.

## Requirements

- Python 3.8 or newer.
- Volatility 3, installed from `requirements.txt` or separately.
- A supported **Windows** memory image for real analysis. No image is bundled.

Install in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
vol -f /path/to/memory.raw windows.info
```

On Windows, activate with `.venv\Scripts\activate` instead. The final command is a quick Volatility check for the image before running MemTriage.

## Usage

```bash
python MemTriage.py --demo
python MemTriage.py /path/to/memory.raw
python MemTriage.py /path/to/memory.raw --report reports/triage.txt --json reports/triage.json
python MemTriage.py /path/to/memory.raw --redact-cmdline --report reports/triage.txt --json reports/triage.json
python MemTriage.py /path/to/memory.raw --vol /path/to/vol.py
```

Create `reports/` before writing there. By default, Volatility's `vol` command must be on `PATH`; `--vol` accepts either its executable or a `vol.py` path. Each plugin has a five-minute timeout. The tool does not run commands inside the memory image or upload evidence.

`--redact-cmdline` replaces command-line values in the console, text report, and JSON report. Other fields, including file paths and network addresses, can still be sensitive. Treat memory images and reports as case evidence and avoid committing them to Git.

## Output and limitations

The text report lists processes by heuristic score, observations, and plugin coverage. JSON includes `findings`, `plugin_errors`, `plugin_coverage`, and `incomplete`; each indicator carries its source plugin, row index, and rule. A failed or incompatible plugin makes the analysis incomplete. JSON findings contain flagged processes rather than a full process inventory.

This is Windows-only and uses heuristic rules rather than signature verification or behavioral proof. It has passed syntax checks, demo mode, focused logic checks, and a command-line smoke test using **mock Volatility JSON**. It has **not** been validated against a real memory image. Volatility versions or image formats may change output fields; inspect plugin coverage before using rankings for decisions.

## Tests

```bash
python -m unittest discover -s tests -v
```

The smoke test creates a dummy image and a fake Volatility command to verify the CLI and report flow. It does not substitute for a real-image validation.

## License

No license is included. Choose and add a license if you want to grant reuse rights to others.
