# Save Architect

Save Architect is an evidence-driven platform for identifying, analyzing, and eventually generating safe browser-based editors for game save files.

## Current milestone: Foundation / ingestion

The first milestone intentionally does **not** claim universal save editing. It provides a reliable ingestion and fingerprinting core that:

- hashes every submitted file;
- measures entropy and printable-string density;
- detects common containers and structured formats;
- records archive members without treating filenames as proof of a game;
- preserves original bytes and unknown regions;
- emits a machine-readable analysis report;
- prepares multiple samples for later differential analysis.

The initial research fixture is a user-provided Borderlands 4 save archive containing five YAML members (`1.yaml`, `2.yaml`, `3.yaml`, `4.yaml`, and `profile.yaml`). The filename and user-provided context are stored as claims, not as verified format identification.

## Safety model

Save Architect is for offline save data from games the user owns and is authorized to modify. The project will not include anti-cheat bypasses, live-service manipulation, account impersonation, or platform-signature circumvention.

## Repository layout

```text
src/savearchitect/       Core Python analysis package
samples/manifests/       Metadata-only manifests for research samples
tests/                   Automated tests
docs/                    Architecture and milestone documents
```

## Run locally

```bash
python -m savearchitect.cli analyze path/to/save-or-archive --output report.json
```

Python 3.11 or newer is recommended.

## Roadmap

1. Ingestion, hashing, format detection, archive inventory
2. Multi-sample differential analysis
3. Field hypotheses with confidence and evidence
4. Declarative parser/serializer definitions
5. Validation, backup, and byte-preservation guarantees
6. Generated browser editors for confirmed definitions
7. Version and platform variant learning
