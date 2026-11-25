# AI usage: dsc26-cyb-w04

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

<!-- Which AI tools you used (or "none"), and for which parts of the task. -->I used Claude to guide me to write triage/core.py and triage/__main__.py from the task spec, I ran the public tests myself and all 5 passed


## What AI got wrong

<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->It told me to run `pip install -r requirements.txt`, which installed the packages outside my `.venv`, so `python -m pytest` said "No module named pytest". I noticed from the error in the terminal and fixed it with `python -m pip install -r requirements.txt`

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Bandit rates the MD5 in `etag()` HIGH and `DB_PASSWORD` LOW. Which would you fix first in Diwan's code, and why?
I would fix the DB_PASSWORD first because exposing a database password can allow attackers to access the database, The MD5 in etag() is less risky if it is only used for caching

2. Why does a suppression need an expiry date?
A suppression needs an expiry date so that security issues don’t stay hidden forever. It makes sure the issue is checked again later and fixed if needed