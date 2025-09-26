# Match & Replace (Repeater) — Burp Suite 

A Burp Suite extension (Jython) that adds a Match&Replace tab in Repeater (requests only). It allows replacing text only within the selection and ensures changes persist when switching back to Pretty/Raw/Hex view.

## TL;DR

- Adds a Match&Replace tab in Repeater → Requests.
- Two fields: Match and Replace, plus an Apply Replace button.
- Replaces only inside the selection (does nothing if nothing is selected).

## Requirements

- Burp Suite (Community or Pro).
- Jython standalone (e.g., jython-standalone-2.7.3.jar) configured in Burp (Extender → Options → Python environment).

## Quick Usage

1. In Repeater, select a portion of the request (headers or body).
2. Open the Match&Replace tab. You will see the request in the native editor.
3. Enter the text to search in Match and the replacement in Replace.
4. Click Apply Replace.
5. If no selection exists, it will prompt you to select a region.
6. Only occurrences inside the selection are replaced.

## License

MIT — free to use and modify, with attribution.
