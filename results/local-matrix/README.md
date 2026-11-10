# Preliminary host evaluation snapshot

Source session: `matrix-20261110-231635`, started November 10, 2026.
See `session.json` for the harness configuration.

Generated with:

```powershell
py eval/analyze.py runs/matrix-20261110-231635 --out results/local-matrix
```

One trial per cell; 28 planned cells, 27 included in the aggregate.
`runs.csv` retains the excluded physics-only flooding result and its validity
flags. A 100% rate here represents a single trial, not an estimated reliability.

These files are preserved as generated. In particular, the timing tables and
plots contain anomalous response times near 2^32 microseconds and deadline
counts. They are diagnostic artifacts, not evidence of hardware timing or
schedulability. The analyzer's reset flag has not been independently confirmed.

Replay detection did not prevent large temperature deviations. Legitimate
ambient disturbances triggered false alarms with physics enabled and poor
mitigation. See the repository README for the interpretation and limitations.

`roc.png` is an offline threshold sweep of the same logged session, not an
independent validation experiment. Raw telemetry is ignored by Git and is not
included in this snapshot; rerunning analysis requires the original local run
folder or a new evaluation session.
