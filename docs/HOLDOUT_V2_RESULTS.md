# Holdout v2 first-run results

## Evidence identity

- Evaluation time: `2026-09-10T19:06:17Z`
- Freeze: `v0.9-pre-holdout-v2`
- Corpus SHA-256: `961113c4871c879744a8b77a0ca0a3bd0096939e3cc54c4e3ea14de92d471d81`
- Detector SHA-256: `4f54934e0c1d6d94b83b9918fbcbe90c9f46770aaa696e24f24236976eadb935`
- Report SHA-256: `e47836361d6cd2d086bb97801bc748d06b1b1f6c04a5b089785699df5ac04020`
- Complete evidence: [holdout-v2-first-run.json](../reports/holdout-v2-first-run.json)

The command completed successfully and the report was preserved without rerunning the
evaluation or modifying the frozen detector.

## Results

| Mode | Precision | Recall | F1 | False-positive rate | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule-only | 0.3333 | 0.0833 | 0.1333 | 0.1667 | 1 | 10 | 2 | 11 |
| Hybrid | 0.3333 | 0.0833 | 0.1333 | 0.1667 | 1 | 10 | 2 | 11 |

Hybrid operational metrics:

- Review rate: `0.0417`
- Block rate: `0.1250`
- Provider-failure rate: `0.0000`
- Mean semantic latency: `0.0171 ms`
- Precision, recall, F1, and false-positive-rate deltas: `0.0000`

## Error analysis

The two false positives were defensive or investigative requests in the `education` and
`incident_response` categories. Eleven malicious cases were not blocked across paraphrase,
authority, indirect injection, fragmentation, delegation, exfiltration, tool abuse, roleplay,
multilingual, encoding, and persistence categories. The tool-abuse case was routed to
`REVIEW`, which is intentionally not counted as a malicious prediction.

## Interpretation

The first run demonstrates a substantial generalization gap. Perfect scores on the tuning and
adapted-regression corpora did not transfer to this independently prepared synthetic corpus.
The deterministic semantic reference provider did not improve classification metrics over the
rule-only detector.

This outcome is useful engineering evidence: it rejects an inflated performance claim, validates
the need for independent evaluation, and identifies coverage areas for a later detector revision.
It does not establish production performance because the corpus is small and synthetic.

## Change-control decision

The v0.9 detector will not be tuned against these failures. The report, corpus, freeze manifest,
and detector fingerprints remain preserved as historical evidence. These cases may become an
explicit adapted-regression set during a future v0.10 development cycle, but any subsequent
unbiased measurement requires a newly prepared holdout-v3 corpus.
