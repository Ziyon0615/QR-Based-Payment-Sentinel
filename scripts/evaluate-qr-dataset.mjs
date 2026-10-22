import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import jsQR from "jsqr";
import sharp from "sharp";
import { analyzePayload } from "../backend/engine.mjs";

const DEFAULT_DATASET_PATH = path.join(process.cwd(), "datasets", "qr-evaluation");
const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg"]);

async function isDirectory(candidate) {
  try {
    return (await fs.stat(candidate)).isDirectory();
  } catch {
    return false;
  }
}

async function findLabelDirectory(root, label) {
  const names = [label, `${label}_qr_images_500`];
  for (const name of names) {
    const candidate = path.join(root, name);
    if (await isDirectory(candidate)) return candidate;
  }

  const children = await fs.readdir(root, { withFileTypes: true });
  for (const child of children.filter((entry) => entry.isDirectory())) {
    for (const name of names) {
      const candidate = path.join(root, child.name, name);
      if (await isDirectory(candidate)) return candidate;
    }
  }

  throw new Error(`Could not find a ${label} image folder inside ${root}.`);
}

async function listImages(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && IMAGE_EXTENSIONS.has(path.extname(entry.name).toLowerCase()))
    .map((entry) => path.join(directory, entry.name))
    .sort((left, right) => left.localeCompare(right, undefined, { numeric: true }));
}

async function decodeQr(file) {
  const { data, info } = await sharp(file).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return jsQR(
    new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength),
    info.width,
    info.height,
    { inversionAttempts: "attemptBoth" },
  )?.data || null;
}

function percentage(numerator, denominator) {
  return denominator ? Number(((numerator / denominator) * 100).toFixed(2)) : 0;
}

async function evaluate(datasetPath) {
  const rows = [];

  for (const expected of ["benign", "malicious"]) {
    const directory = await findLabelDirectory(datasetPath, expected);
    const files = await listImages(directory);

    for (const file of files) {
      let payload = null;
      let analysis = null;
      let error = null;

      try {
        payload = await decodeQr(file);
        if (!payload) {
          error = "QR payload could not be decoded";
        } else {
          analysis = await analyzePayload(payload, {
            resolveRedirects: false,
            lookupIocs: async () => [],
          });
        }
      } catch (caught) {
        error = caught instanceof Error ? caught.message : String(caught);
      }

      rows.push({ expected, file: path.basename(file), decoded: Boolean(payload), analysis, error });
    }
  }

  const decodedRows = rows.filter((row) => row.analysis);
  const actualBenign = decodedRows.filter((row) => row.expected === "benign");
  const actualMalicious = decodedRows.filter((row) => row.expected === "malicious");
  const predictsRisk = (row) => row.analysis.classification !== "Safe";
  const truePositive = actualMalicious.filter(predictsRisk).length;
  const falseNegative = actualMalicious.length - truePositive;
  const falsePositive = actualBenign.filter(predictsRisk).length;
  const trueNegative = actualBenign.length - falsePositive;
  const classifications = { Safe: 0, Suspicious: 0, Malicious: 0 };
  const indicators = {};

  for (const row of decodedRows) {
    classifications[row.analysis.classification] += 1;
    for (const item of row.analysis.indicators) indicators[item.id] = (indicators[item.id] || 0) + 1;
  }

  return {
    mode: "offline",
    networkRequests: false,
    datasetPath,
    evaluatedAt: new Date().toISOString(),
    totals: {
      files: rows.length,
      decoded: decodedRows.length,
      decodeFailures: rows.length - decodedRows.length,
      benign: actualBenign.length,
      malicious: actualMalicious.length,
    },
    classifications,
    confusionMatrix: { truePositive, falseNegative, falsePositive, trueNegative },
    metrics: {
      accuracyPercent: percentage(truePositive + trueNegative, decodedRows.length),
      maliciousRecallPercent: percentage(truePositive, actualMalicious.length),
      benignFalsePositiveRatePercent: percentage(falsePositive, actualBenign.length),
    },
    topIndicators: Object.entries(indicators)
      .sort((left, right) => right[1] - left[1])
      .slice(0, 10)
      .map(([id, count]) => ({ id, count })),
    failures: rows.filter((row) => row.error).map(({ expected, file, error }) => ({ expected, file, error })),
  };
}

function printReport(report) {
  const matrix = report.confusionMatrix;
  console.log("QR Sentinel offline dataset evaluation");
  console.log("No decoded URL was opened and redirect resolution was disabled.\n");
  console.table([
    { expected: "Benign", total: report.totals.benign, safe: matrix.trueNegative, risky: matrix.falsePositive },
    { expected: "Malicious", total: report.totals.malicious, safe: matrix.falseNegative, risky: matrix.truePositive },
  ]);
  console.table(report.classifications);
  console.log(`Decoded: ${report.totals.decoded}/${report.totals.files}`);
  console.log(`Accuracy: ${report.metrics.accuracyPercent}%`);
  console.log(`Malicious recall: ${report.metrics.maliciousRecallPercent}%`);
  console.log(`Benign false-positive rate: ${report.metrics.benignFalsePositiveRatePercent}%`);
  console.log("\nTop triggered indicators:");
  console.table(report.topIndicators);
  if (report.failures.length) console.log(`\nDecode failures: ${report.failures.length}`);
}

function parseArguments(argumentsList) {
  const positional = [];
  let output = null;
  for (let index = 0; index < argumentsList.length; index += 1) {
    if (argumentsList[index] === "--json") {
      output = argumentsList[index + 1] || null;
      index += 1;
    } else {
      positional.push(argumentsList[index]);
    }
  }
  return { datasetPath: path.resolve(positional[0] || process.env.QR_DATASET_PATH || DEFAULT_DATASET_PATH), output };
}

const { datasetPath, output } = parseArguments(process.argv.slice(2));

try {
  if (!(await isDirectory(datasetPath))) throw new Error(`Dataset directory does not exist: ${datasetPath}`);
  const report = await evaluate(datasetPath);
  printReport(report);
  if (output) {
    const outputPath = path.resolve(output);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(`\nJSON report: ${outputPath}`);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
