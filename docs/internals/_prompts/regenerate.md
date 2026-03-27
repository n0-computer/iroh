# Regeneration Instructions for Iroh Internals Docs

You are regenerating a section of iroh's internal documentation. Follow these rules:

## General Rules

1. Only modify content between `<!-- BEGIN GENERATED SECTION -->` and `<!-- END GENERATED SECTION -->` markers.
2. Never modify human-written prose outside these markers.
3. Read the source files listed in the `Source:` field of the section's HTML comment.
4. Follow the `Prompt:` instructions in the HTML comment to determine what to extract.
5. Preserve the section's HTML comment (the metadata block) exactly as-is.

## Mermaid Diagram Rules

1. Use `stateDiagram-v2` for state machines.
2. Use `sequenceDiagram` for protocol flows.
3. Use `flowchart TD` for decision flows.
4. Keep node labels short but descriptive.
5. Include transition labels showing the method/event that triggers each transition.
6. Use notes for important constants (timeouts, thresholds).

## Accuracy Rules

1. Every state in a diagram must correspond to an actual variant, field, or documented state in the code.
2. Every transition must correspond to an actual code path (method call, match arm, event handler).
3. Include relevant constants (timeouts, thresholds) from the source.
4. If the code has changed and a state/transition no longer exists, remove it.
5. If new states/transitions exist in the code, add them.

## Style Rules

1. After each diagram, include a brief "States" or "Transitions" reference table.
2. Reference source locations as `file_path:line_number` where helpful.
3. Keep descriptions factual — describe what the code does, not what it should do.
