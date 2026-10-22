# QR evaluation datasets

The image files used for offline evaluation are intentionally excluded from Git and production deployments.

## Current dataset

- Source: [Dataset of 1000 Images of Malicious and Benign QR codes 2025](https://data.mendeley.com/datasets/cmhh7744sp/1)
- Author: Sefiya Galadima
- Version: 1, published February 20, 2025
- DOI: `10.17632/cmhh7744sp.1`
- License: CC BY 4.0

Extract the dataset into `datasets/qr-evaluation/`. The evaluator accepts either of these folder layouts:

```text
datasets/qr-evaluation/
├── benign/
└── malicious/
```

```text
datasets/qr-evaluation/
├── benign_qr_images_500/
└── malicious_qr_images_500/
```

Run the offline evaluation:

```powershell
npm run evaluate:qr-dataset
```

Or provide another extracted dataset path and optionally save a JSON report:

```powershell
npm run evaluate:qr-dataset -- "C:\path\to\dataset" --json "reports\qr-evaluation.json"
```

The evaluator decodes images locally. It disables redirect resolution, performs no URL requests, and does not add dataset entries to the active threat-intelligence feed.
