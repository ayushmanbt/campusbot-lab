# CampusBot Security Lab

An offline, educational lab demonstrating prompt injection attacks and the
defence layers used to mitigate them. Run it only against this local mock
application and its supplied test data.

## Launch in Google Colab

Create a fresh Colab notebook with this link:

[Open a new Google Colab notebook](https://colab.research.google.com/#create=true)

Then paste this into the first code cell and run it:

```python
!git clone https://github.com/ayushmanbt/campusbot-lab.git /content/campusbot-lab
%cd /content/campusbot-lab/
```

The guided notebooks include this setup automatically. No API key or external
LLM is required.

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