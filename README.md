# QRBased Sentinel

QRBased Sentinel is a mobile-compatible research prototype for real-time detection and explainable risk assessment of QR payment payloads. It implements the framework described in the study: payload decoding, payment-context validation, redirect analysis, local cyber-threat-intelligence enrichment, IoC matching, and 0-100 risk scoring.

## Local development

Requirements: Node.js 22.13 or newer.

1. Copy `.env.example` to `.env.local` if you need to change the default ports.
2. Run `npm install`.
3. Run `npm run dev`.
4. Open `http://localhost:3000`. The local API runs on `http://localhost:8000`.

The SQLite database is created automatically at `data/qr-sentinel.db`. The `data/` directory is excluded from version control.

## Running the system again in VS Code

1. Open the `QR Sentinel` folder in Visual Studio Code.
2. Open the integrated terminal by selecting **Terminal > New Terminal**.
3. Confirm that the terminal is inside the project folder. If it is not, run:

   ```powershell
   cd "C:\Users\Diony\Desktop\QR Sentinel"
   ```

4. Start the frontend and backend together:

   ```powershell
   npm run dev
   ```

5. Open `http://localhost:3000` in your browser.

Keep the terminal open while using the system. Press `Ctrl+C` in the terminal to stop it.

You normally only need to run `npm install` during the first setup or after the project dependencies change. If `node_modules` is missing, run:

```powershell
npm install
npm run dev
```

## What the prototype includes

- Mobile camera scanning and QR image upload using the browser Barcode Detection API
- Manual analysis for decoded URLs, deep links, and EMV merchant-presented payloads
- EMV TLV parsing, required-field checks, and CRC-16/CCITT validation
- URL lexical, domain, parameter, URI-scheme, and redirect-chain indicators
- Server-side redirect inspection with private/local network blocking and a five-hop limit
- Local SQLite IoC store for domains, URLs, and IP addresses
- Explainable Safe (0-39), Suspicious (40-69), and Malicious (70-100) results
- Scan history, latency summaries, confusion matrix, accuracy, precision, recall, F1, FPR, and FNR
- Optional expected labels for controlled academic evaluation

## Safety boundary

The application does not authorize or process payments, collect credentials, or automatically open scanned destinations. Use malicious samples only in controlled research conditions. Live redirect checks inspect HTTP response headers only and reject private or local network destinations.

## Later deployment path

The frontend is a standard Next.js application suitable for Vercel. The Node API can run on Render. For production, replace the SQLite repository in `backend/database.mjs` with a Neon Postgres repository while preserving the API contract. Set `NEXT_PUBLIC_API_URL` to the Render service URL and `ALLOWED_ORIGINS` to the Vercel domain.

## Validation

- `npm test` runs risk-engine tests.
- `npm run build` creates the production frontend build.
