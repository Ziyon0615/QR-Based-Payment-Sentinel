type FinderCandidate = { x: number; y: number; size: number };
type FinderCluster = FinderCandidate & { hits: number };

function matchesFinderRatio(runs: number[]) {
  const total = runs.reduce((sum, run) => sum + run, 0);
  if (total < 7) return false;
  const moduleSize = total / 7;
  const tolerance = moduleSize * 0.8;
  return Math.abs(runs[0] - moduleSize) <= tolerance
    && Math.abs(runs[1] - moduleSize) <= tolerance
    && Math.abs(runs[2] - moduleSize * 3) <= tolerance * 3
    && Math.abs(runs[3] - moduleSize) <= tolerance
    && Math.abs(runs[4] - moduleSize) <= tolerance;
}

export function locateQrFinderPatterns(data: Uint8ClampedArray, sourceWidth: number, sourceHeight: number) {
  if (sourceWidth < 21 || sourceHeight < 21) return [];
  const sampleStep = Math.max(1, Math.ceil(Math.max(sourceWidth, sourceHeight) / 640));
  const width = Math.floor(sourceWidth / sampleStep);
  const height = Math.floor(sourceHeight / sampleStep);
  const luminance = new Uint8Array(width * height);
  const histogram = new Uint32Array(256);

  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const offset = ((y * sampleStep) * sourceWidth + x * sampleStep) * 4;
      const value = Math.round(data[offset] * 0.299 + data[offset + 1] * 0.587 + data[offset + 2] * 0.114);
      luminance[y * width + x] = value;
      histogram[value] += 1;
    }
  }

  const totalPixels = width * height;
  let weightedTotal = 0;
  for (let value = 0; value < 256; value += 1) weightedTotal += value * histogram[value];
  let backgroundWeight = 0;
  let backgroundTotal = 0;
  let bestVariance = -1;
  let threshold = 128;
  for (let value = 0; value < 256; value += 1) {
    backgroundWeight += histogram[value];
    if (!backgroundWeight) continue;
    const foregroundWeight = totalPixels - backgroundWeight;
    if (!foregroundWeight) break;
    backgroundTotal += value * histogram[value];
    const backgroundMean = backgroundTotal / backgroundWeight;
    const foregroundMean = (weightedTotal - backgroundTotal) / foregroundWeight;
    const variance = backgroundWeight * foregroundWeight * (backgroundMean - foregroundMean) ** 2;
    if (variance > bestVariance) { bestVariance = variance; threshold = value; }
  }

  const isDark = (x: number, y: number) => luminance[y * width + x] <= threshold;
  const crossCheckDiagonal = (centerX: number, centerY: number, deltaY: number, expectedTotal: number) => {
    const x = Math.round(centerX);
    const y = Math.round(centerY);
    const inBounds = (column: number, row: number) => column >= 0 && column < width && row >= 0 && row < height;
    if (!inBounds(x, y) || !isDark(x, y)) return false;
    const runs = [0, 0, 0, 0, 0];
    let column = x;
    let row = y;
    while (inBounds(column, row) && isDark(column, row)) { runs[2] += 1; column -= 1; row -= deltaY; }
    while (inBounds(column, row) && !isDark(column, row)) { runs[1] += 1; column -= 1; row -= deltaY; }
    while (inBounds(column, row) && isDark(column, row)) { runs[0] += 1; column -= 1; row -= deltaY; }
    column = x + 1; row = y + deltaY;
    while (inBounds(column, row) && isDark(column, row)) { runs[2] += 1; column += 1; row += deltaY; }
    while (inBounds(column, row) && !isDark(column, row)) { runs[3] += 1; column += 1; row += deltaY; }
    while (inBounds(column, row) && isDark(column, row)) { runs[4] += 1; column += 1; row += deltaY; }
    const total = runs.reduce((sum, run) => sum + run, 0);
    return matchesFinderRatio(runs) && Math.abs(total - expectedTotal) <= expectedTotal * 0.65;
  };
  const crossCheckVertical = (centerX: number, centerY: number, expectedTotal: number) => {
    const x = Math.round(centerX);
    const y = Math.round(centerY);
    if (x < 0 || x >= width || y < 0 || y >= height || !isDark(x, y)) return null;
    const runs = [0, 0, 0, 0, 0];
    let cursor = y;
    while (cursor >= 0 && isDark(x, cursor)) { runs[2] += 1; cursor -= 1; }
    while (cursor >= 0 && !isDark(x, cursor)) { runs[1] += 1; cursor -= 1; }
    while (cursor >= 0 && isDark(x, cursor)) { runs[0] += 1; cursor -= 1; }
    cursor = y + 1;
    while (cursor < height && isDark(x, cursor)) { runs[2] += 1; cursor += 1; }
    while (cursor < height && !isDark(x, cursor)) { runs[3] += 1; cursor += 1; }
    while (cursor < height && isDark(x, cursor)) { runs[4] += 1; cursor += 1; }
    const total = runs.reduce((sum, run) => sum + run, 0);
    if (!matchesFinderRatio(runs) || Math.abs(total - expectedTotal) > expectedTotal * 0.65) return null;
    const adjustedY = cursor - runs[4] - runs[3] - runs[2] / 2;
    if (!crossCheckDiagonal(x, adjustedY, 1, total) && !crossCheckDiagonal(x, adjustedY, -1, total)) return null;
    return { y: Math.max(0, Math.min(height - 1, adjustedY)), total };
  };

  const candidates: FinderCandidate[] = [];
  for (let y = 0; y < height; y += 1) {
    const runs: number[] = [];
    const colors: boolean[] = [];
    let currentColor = isDark(0, y);
    let currentRun = 1;
    const inspectRun = (endX: number) => {
      runs.push(currentRun); colors.push(currentColor);
      if (runs.length > 5) { runs.shift(); colors.shift(); }
      if (runs.length === 5 && colors[0] && !colors[1] && colors[2] && !colors[3] && colors[4] && matchesFinderRatio(runs)) {
        const total = runs.reduce((sum, run) => sum + run, 0);
        const centerX = endX - runs[4] - runs[3] - runs[2] / 2;
        const vertical = crossCheckVertical(centerX, y, total);
        if (vertical) candidates.push({ x: centerX, y: vertical.y, size: (total + vertical.total) / 2 });
      }
    };
    for (let x = 1; x <= width; x += 1) {
      const nextColor = x < width ? isDark(x, y) : !currentColor;
      if (x < width && nextColor === currentColor) currentRun += 1;
      else {
        inspectRun(x);
        currentColor = nextColor;
        currentRun = 1;
      }
    }
  }

  const clusters: FinderCluster[] = [];
  for (const candidate of candidates) {
    const cluster = clusters.find((item) => Math.hypot(item.x - candidate.x, item.y - candidate.y) <= Math.max(3, Math.max(item.size, candidate.size) * 0.45));
    if (cluster) {
      const hits = cluster.hits + 1;
      cluster.x = (cluster.x * cluster.hits + candidate.x) / hits;
      cluster.y = (cluster.y * cluster.hits + candidate.y) / hits;
      cluster.size = (cluster.size * cluster.hits + candidate.size) / hits;
      cluster.hits = hits;
    } else {
      clusters.push({ ...candidate, hits: 1 });
    }
  }
  return clusters.filter(({ hits, size }) => hits >= 2 && size >= 7);
}

export function countQrFinderPatterns(data: Uint8ClampedArray, sourceWidth: number, sourceHeight: number) {
  return locateQrFinderPatterns(data, sourceWidth, sourceHeight).length;
}

export function countVisibleQrCodes(data: Uint8ClampedArray, sourceWidth: number, sourceHeight: number) {
  const patterns = locateQrFinderPatterns(data, sourceWidth, sourceHeight);
  const groups: { indices: number[]; quality: number }[] = [];
  for (let first = 0; first < patterns.length - 2; first += 1) {
    for (let second = first + 1; second < patterns.length - 1; second += 1) {
      for (let third = second + 1; third < patterns.length; third += 1) {
        const points = [patterns[first], patterns[second], patterns[third]];
        const sizes = points.map(({ size }) => size);
        if (Math.max(...sizes) / Math.min(...sizes) > 1.15) continue;
        const squaredDistances = [
          (points[0].x - points[1].x) ** 2 + (points[0].y - points[1].y) ** 2,
          (points[0].x - points[2].x) ** 2 + (points[0].y - points[2].y) ** 2,
          (points[1].x - points[2].x) ** 2 + (points[1].y - points[2].y) ** 2,
        ].sort((a, b) => a - b);
        const averageSize = sizes.reduce((sum, size) => sum + size, 0) / sizes.length;
        if (Math.sqrt(squaredDistances[0]) < averageSize * 1.5) continue;
        const legBalance = squaredDistances[0] / squaredDistances[1];
        const rightAngleError = Math.abs(squaredDistances[2] - squaredDistances[0] - squaredDistances[1]) / (squaredDistances[0] + squaredDistances[1]);
        if (legBalance < 0.35 || rightAngleError > 0.3) continue;
        groups.push({ indices: [first, second, third], quality: rightAngleError + Math.abs(Math.log(legBalance)) * 0.2 });
      }
    }
  }

  const usedPatterns = new Set<number>();
  let count = 0;
  for (const group of groups.sort((a, b) => a.quality - b.quality)) {
    if (group.indices.some((index) => usedPatterns.has(index))) continue;
    group.indices.forEach((index) => usedPatterns.add(index));
    count += 1;
  }
  return count;
}
