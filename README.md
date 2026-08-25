# CampusBot Security Lab

An offline, educational lab demonstrating prompt injection attacks and the
defence layers used to mitigate them. Run it only against this local mock
application and its supplied test data.

## Launch in Google Colab

<a href="https://colab.research.google.com/drive/1MfcGhK9BJ7eTPb_QiB0tKdXLn3eNRE2x?usp=sharing&copy=true" target="_blank">Session 1 Notebook</a>

<a href="https://colab.research.google.com/drive/1NMT_uWVi3QTe_FdyKOeuiaFno6NSnE-F?usp=sharing&copy=true" target="_blank">Session 2 Notebook</a>

## Run locally

From this directory, use Python 3.10 or newer:

```bash
python session1_attack.py
python session2_defense.py
```

The scripts use `mock_llm.py`, so all model responses and attacker-server logs
remain local. The `tests` directory contains the automated checks:

```bash
pytest -q
```

## Project map

- `session1_attack.ipynb`: vulnerable baseline and direct/indirect attacks
- `session2_defense.ipynb`: defence configuration and attack re-run
- `campusbot.py`: intentionally vulnerable CampusBot
- `campusbot_secure.py`: defended CampusBot
- `defenses.py`: hidden-text and injection-detection helpers
- `corpus/`: trusted campus documents
- `attacks/`: supplied attack fixtures

This project is for authorized, local, offline security training only.