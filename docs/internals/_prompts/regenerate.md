# Regeneration Instructions for Iroh Internals Docs

You are regenerating a section of iroh's internal documentation. Follow these rules:

## General Rules

1. Only modify content between `<!-- BEGIN GENERATED SECTION -->` and `<!-- END GENERATED SECTION -->` markers.
2. Never modify human-written prose outside these markers.
3. Read the source files listed in the `Source:` field of the section's HTML comment.
4. Follow the `Prompt:` instructions in the HTML comment to determine what to extract.
5. Preserve the section's HTML comment (the metadata block) exactly as-is.

## SVG Diagram Rules

All diagrams are hand-crafted SVG files in `docs/internals/diagrams/`. No external tools
(mermaid, graphviz, npm packages) are used — the LLM generates the SVG directly.

### Color Palette (matches iroh.computer brand)

```
Dark background:   #1a1a2e    (deep navy)
Panel/card bg:     #252542    (slightly lighter navy)
Primary accent:    #7C7CFF    (iroh purple)
Secondary accent:  #5454C6    (darker purple, for less prominent elements)
Light accent:      #9494F7    (lighter purple, hover/highlight)
Success/active:    #4ADE80    (green — active/open states)
Warning:           #FBBF24    (amber — transitional states)
Error/unusable:    #F87171    (red — error/failed states)
Text primary:      #E2E2F0    (light gray-lavender)
Text secondary:    #9494A8    (muted gray)
Text on accent:    #FFFFFF    (white)
Arrow/line:        #7C7CFF    (purple, opacity 0.6 for non-primary)
Arrow highlight:   #9494F7    (light purple, for key transitions)
Note bg:           #2a2a4a    (dark blue-gray)
Note border:       #7C7CFF    (purple, dashed)
```

### Fonts

```
font-family: system-ui, -apple-system, sans-serif
State labels:      14px, font-weight 600, fill #E2E2F0
Transition labels: 11px, fill #9494A8
Annotations:       12px, italic, fill #9494F7
Title:             16px, font-weight 700, fill #E2E2F0
```

### Design Principles

1. **3-7 elements per diagram.** If you need more, you're showing too much. Split or simplify.
2. **Annotate the WHY.** Every diagram must have at least one annotation explaining a
   non-obvious design decision or trade-off. The diagram should teach, not just describe.
3. **Capture essence, not structure.** Don't map every struct or enum variant. Show the
   conceptual states and the key transitions a developer needs to understand.
4. **Label transitions with triggers.** Show what causes each transition (method name,
   event, timeout) — not just that it exists.
5. **Include key constants inline.** Timeouts and thresholds that matter should appear
   as annotations near the relevant transition, not in a separate table.

### SVG Template

Every SVG should start with this structure:

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5"
            markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#7C7CFF"/>
    </marker>
    <marker id="arrow-muted" viewBox="0 0 10 10" refX="9" refY="5"
            markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#5454C6"/>
    </marker>
    <style>
      text { font-family: system-ui, -apple-system, sans-serif; }
      .state { fill: #252542; stroke: #7C7CFF; stroke-width: 2; rx: 8; }
      .state-active { fill: #1a3a2a; stroke: #4ADE80; stroke-width: 2; rx: 8; }
      .state-warn { fill: #2a2a1a; stroke: #FBBF24; stroke-width: 2; rx: 8; }
      .state-error { fill: #2a1a1a; stroke: #F87171; stroke-width: 2; rx: 8; }
      .arrow { stroke: #7C7CFF; stroke-width: 1.5; fill: none; marker-end: url(#arrow); }
      .arrow-muted { stroke: #5454C6; stroke-width: 1.5; fill: none;
                     marker-end: url(#arrow-muted); stroke-dasharray: 4 2; }
      .label { font-size: 14px; font-weight: 600; fill: #E2E2F0; text-anchor: middle; }
      .label-sm { font-size: 11px; fill: #9494A8; text-anchor: middle; }
      .note { fill: #2a2a4a; stroke: #7C7CFF; stroke-width: 1; stroke-dasharray: 4 2; rx: 4; }
      .note-text { font-size: 12px; fill: #9494F7; font-style: italic; }
      .title { font-size: 16px; font-weight: 700; fill: #E2E2F0; }
    </style>
  </defs>
  <rect width="100%" height="100%" fill="#1a1a2e"/>

  <!-- diagram content here -->
</svg>
```

### Validation

All SVGs must pass `xmllint --noout <file>`. This is checked by `docs/internals/validate.sh`.

## Accuracy Rules

1. Every state in a diagram must correspond to an actual variant, field, or documented state in the code.
2. Every transition must correspond to an actual code path (method call, match arm, event handler).
3. Include relevant constants (timeouts, thresholds) from the source.
4. If the code has changed and a state/transition no longer exists, remove it.
5. If new states/transitions exist in the code, add them.

## Content Rules

1. After each diagram, include a brief reference table only if it adds info beyond the diagram.
2. Keep descriptions factual — describe what the code does, not what it should do.
3. Don't repeat what the diagram already shows. The prose should add context the diagram can't.
