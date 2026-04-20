import { pipeline } from "https://cdn.jsdelivr.net/npm/@huggingface/transformers@4.1.0";

// ELEMENTS
const btnScan = document.getElementById("btnScan");
const btnEvaluate = document.getElementById("btnEvaluate");
const btnFalsePositive = document.getElementById("btnFalsePositive");
const btnThreat = document.getElementById("btnThreat");
const btnReset = document.getElementById("btnReset");

const scanStatus = document.getElementById("scanStatus");

const detectedTimeEl = document.getElementById("detectedTime");
const deviceStatusEl = document.getElementById("deviceStatus");
const locationSel = document.getElementById("location");

const targetPhraseEl = document.getElementById("targetPhrase");
const typingInputEl = document.getElementById("typingInput");
const typingStatusEl = document.getElementById("typingStatus");

const riskScoreEl = document.getElementById("riskScore");
const decisionEl = document.getElementById("decision");
const thresholdEl = document.getElementById("threshold");
const factorsEl = document.getElementById("factors");
const aiOutputEl = document.getElementById("aiOutput");
const logEl = document.getElementById("log");

const fpCountEl = document.getElementById("fpCount");
const threatCountEl = document.getElementById("threatCount");
const sensitivityEl = document.getElementById("sensitivity");
const prevThresholdEl = document.getElementById("prevThreshold");
const thresholdChangeEl = document.getElementById("thresholdChange");

// STATE
let threshold = 60;
let scanned = false;
let falsePositives = 0;
let confirmedThreats = 0;
let feedbackApplied = false;
let currentDecision = "";
let extractor = null;

let detectedLoginTime = "normal";
let detectedDevice = "known";
let typingPattern = "normal";

let typingStartTime = null;
let keyTimestamps = [];
let backspaceCount = 0;

const targetPhrase = "my login is secure";

// Reference examples
const SAFE_EXAMPLES = [
  "Routine login during normal business hours from a recognized device in the user's usual location with normal typing behavior and no anomalies detected.",
  "Expected account access from a trusted device, familiar region, standard work hours, and behavior matching the legitimate user's typing profile.",
  "Normal authentication session with no suspicious indicators: known device, usual location, normal access time, and consistent behavioral pattern.",
  "Legitimate user login from a previously approved device in a normal area during expected hours with stable typing rhythm.",
  "Low-risk login session that matches the account owner's normal behavior, location, device history, and timing."
];

const RISKY_EXAMPLES = [
  "Suspicious login attempt late at night from a new device in an unusual location with abnormal typing behavior and multiple security anomalies.",
  "Possible account takeover using an unrecognized device, unexpected region, off-hours access, and behavior inconsistent with the legitimate user.",
  "High-risk authentication session with several anomaly indicators including device mismatch, location mismatch, unusual timing, and typing inconsistency.",
  "Potential fraudulent access from an unseen device outside the user's normal area during an unusual time with behavior that does not match the normal profile.",
  "Dangerous login pattern suggesting account compromise due to multiple behavioral and contextual anomalies."
];

// HELPERS
function log(message) {
  const li = document.createElement("li");
  li.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.prepend(li);
}

function detectLoginTime() {
  const hour = new Date().getHours();
  detectedLoginTime = (hour >= 23 || hour < 5) ? "late" : "normal";
  detectedTimeEl.value = detectedLoginTime === "late" ? "Late Night / Off-Hours" : "Normal Access Hours";
}

function getDeviceFingerprint() {
  return `${navigator.userAgent}|${navigator.language}|${screen.width}x${screen.height}`;
}

function detectDeviceFamiliarity() {
  const key = "sip_known_device_fingerprint";
  const currentFingerprint = getDeviceFingerprint();
  const savedFingerprint = localStorage.getItem(key);

  if (!savedFingerprint) {
    localStorage.setItem(key, currentFingerprint);
    detectedDevice = "known";
    deviceStatusEl.value = "Known Device (first stored browser fingerprint)";
  } else if (savedFingerprint === currentFingerprint) {
    detectedDevice = "known";
    deviceStatusEl.value = "Known Device";
  } else {
    detectedDevice = "new";
    deviceStatusEl.value = "New / Unrecognized Device";
  }
}

function resetTypingCapture() {
  typingPattern = "normal";
  typingStartTime = null;
  keyTimestamps = [];
  backspaceCount = 0;
  typingInputEl.value = "";
  typingStatusEl.textContent = "Waiting for typing sample...";
}

function analyzeTypingPattern() {
  const typedText = typingInputEl.value.trim().toLowerCase();
  const typedLength = typedText.length;
  const targetLength = targetPhrase.length;

  if (typedLength === 0 || keyTimestamps.length < 2) {
    typingPattern = "normal";
    typingStatusEl.textContent = "Not enough typing data yet.";
    return;
  }

  const totalDuration = keyTimestamps[keyTimestamps.length - 1] - keyTimestamps[0];
  const avgInterval = totalDuration / (keyTimestamps.length - 1);
  const tooManyBackspaces = backspaceCount >= 3;
  const phraseMismatch = typedText !== targetPhrase;
  const verySlow = avgInterval > 450;
  const veryFast = avgInterval < 70;

  typingPattern = (tooManyBackspaces || phraseMismatch || verySlow || veryFast) ? "weird" : "normal";

  typingStatusEl.textContent =
    typingPattern === "weird"
      ? `Typing anomaly detected (avg interval ${Math.round(avgInterval)} ms, backspaces ${backspaceCount})`
      : `Typing pattern appears normal (avg interval ${Math.round(avgInterval)} ms, backspaces ${backspaceCount})`;
}

function buildSessionText() {
  const parts = [];

  parts.push(
    detectedLoginTime === "late"
      ? "Login occurred outside normal access hours."
      : "Login occurred during expected access hours."
  );

  parts.push(
    detectedDevice === "new"
      ? "Device is new and not previously recognized."
      : "Device is known and previously trusted."
  );

  parts.push(
    locationSel.value === "unusual"
      ? "Location is unusual compared to prior user activity."
      : "Location matches the user's normal access area."
  );

  parts.push(
    typingPattern === "weird"
      ? "Typing behavior is inconsistent with the normal user profile."
      : "Typing behavior matches the user's normal profile."
  );

  return parts.join(" ");
}

function buildFactors() {
  const factors = [];

  if (detectedLoginTime === "late") factors.push("Off-hours login detected automatically");
  if (detectedDevice === "new") factors.push("New or unrecognized device detected automatically");
  if (locationSel.value === "unusual") factors.push("Location marked as unusual");
  if (typingPattern === "weird") factors.push("Typing rhythm anomaly detected from live typing sample");

  if (factors.length === 0) {
    factors.push("All evaluated session signals fall within normal thresholds.");
  }

  return factors;
}

async function loadModel() {
  try {
    scanStatus.textContent = "Loading AI model...";
    log("Loading real AI embedding model for browser inference...");

    extractor = await pipeline(
      "feature-extraction",
      "Xenova/all-MiniLM-L6-v2"
    );

    scanStatus.textContent = "AI model loaded. Ready for entry approval.";
    btnScan.disabled = false;
    log("AI model loaded successfully.");
  } catch (error) {
    console.error(error);
    scanStatus.textContent = "Failed to load AI model.";
    log("Error: AI model failed to load.");
  }
}

async function getEmbedding(text) {
  const output = await extractor(text, {
    pooling: "mean",
    normalize: true
  });

  return Array.from(output.data);
}

function cosineSimilarity(a, b) {
  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }

  if (magA === 0 || magB === 0) return 0;
  return dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

async function averageSimilarity(sessionEmbedding, examples) {
  let total = 0;

  for (const example of examples) {
    const exampleEmbedding = await getEmbedding(example);
    total += cosineSimilarity(sessionEmbedding, exampleEmbedding);
  }

  return total / examples.length;
}

async function computeRiskWithAI() {
  const sessionText = buildSessionText();
  const sessionEmbedding = await getEmbedding(sessionText);

  const safeSimilarity = await averageSimilarity(sessionEmbedding, SAFE_EXAMPLES);
  const riskySimilarity = await averageSimilarity(sessionEmbedding, RISKY_EXAMPLES);

  let anomalyScore = 0;
  if (detectedLoginTime === "late") anomalyScore += 20;
  if (detectedDevice === "new") anomalyScore += 30;
  if (locationSel.value === "unusual") anomalyScore += 30;
  if (typingPattern === "weird") anomalyScore += 20;

  const aiDelta = riskySimilarity - safeSimilarity;
  const aiAdjustment = Math.round(aiDelta * 15);

  let variation = 0;
  if (anomalyScore === 0) {
    variation = Math.floor(Math.random() * 4);
  } else if (anomalyScore >= 80) {
    variation = Math.floor(Math.random() * 5) - 2;
  } else {
    variation = Math.floor(Math.random() * 7) - 3;
  }

  const finalScore = Math.max(
    0,
    Math.min(100, anomalyScore + aiAdjustment + variation)
  );

  let modelLabel = "AI REVIEW: BORDERLINE";
  if (finalScore <= 15) {
    modelLabel = "AI REVIEW: SAFE PATTERN";
  } else if (finalScore >= 70) {
    modelLabel = "AI REVIEW: RISKY PATTERN";
  }

  return {
    score: finalScore,
    anomalyScore,
    aiAdjustment,
    variation,
    modelLabel,
    sessionText,
    safeSimilarity: safeSimilarity.toFixed(3),
    riskySimilarity: riskySimilarity.toFixed(3),
    confidenceGap: aiDelta.toFixed(3)
  };
}

function render(score, decision, factors) {
  riskScoreEl.textContent = score;
  thresholdEl.textContent = threshold;

  decisionEl.className = "";
  if (decision === "ALLOW") {
    decisionEl.classList.add("allow");
  } else if (decision === "STEP-UP AUTH REQUIRED") {
    decisionEl.classList.add("stepup");
  } else {
    decisionEl.classList.add("flagged");
  }

  decisionEl.textContent = decision;

  factorsEl.innerHTML = "";
  factors.forEach((factor) => {
    const li = document.createElement("li");
    li.textContent = factor;
    factorsEl.appendChild(li);
  });
}

function updateModelStatus() {
  fpCountEl.textContent = falsePositives;
  threatCountEl.textContent = confirmedThreats;

  sensitivityEl.className = "";
  if (threshold >= 75) {
    sensitivityEl.textContent = "Low (Less Sensitive)";
    sensitivityEl.classList.add("low");
  } else if (threshold <= 50) {
    sensitivityEl.textContent = "High (More Sensitive)";
    sensitivityEl.classList.add("high");
  } else {
    sensitivityEl.textContent = "Moderate";
    sensitivityEl.classList.add("moderate");
  }
}

function disableFeedbackButtons() {
  btnFalsePositive.disabled = true;
  btnThreat.disabled = true;
}

function updateFeedbackButtons() {
  if (currentDecision === "FLAGGED" && !feedbackApplied) {
    btnFalsePositive.disabled = false;
    btnThreat.disabled = false;
  } else {
    disableFeedbackButtons();
  }
}

// TYPING EVENTS
typingInputEl.addEventListener("focus", () => {
  if (typingStartTime === null) {
    typingStartTime = performance.now();
  }
});

typingInputEl.addEventListener("keydown", (event) => {
  keyTimestamps.push(performance.now());

  if (event.key === "Backspace") {
    backspaceCount++;
  }
});

typingInputEl.addEventListener("input", () => {
  analyzeTypingPattern();
});

// BUTTON EVENTS
btnScan.onclick = () => {
  scanned = true;
  scanStatus.textContent = "Entry approval complete";
  btnEvaluate.disabled = false;
  log("Simulated passwordless entry approval completed.");
};

btnEvaluate.onclick = async () => {
  if (!scanned || !extractor) return;

  btnEvaluate.disabled = true;
  scanStatus.textContent = "AI model analyzing session...";

  try {
    await new Promise((resolve) => setTimeout(resolve, 1200));

    const aiResult = await computeRiskWithAI();
    const score = aiResult.score;
    const factors = buildFactors();

    if (aiOutputEl) {
      aiOutputEl.textContent = JSON.stringify({
        session: aiResult.sessionText,
        safeSimilarity: aiResult.safeSimilarity,
        riskySimilarity: aiResult.riskySimilarity,
        confidenceGap: aiResult.confidenceGap,
        aiAdjustment: aiResult.aiAdjustment,
        modelDecision: aiResult.modelLabel
      }, null, 2);
    }

    if (score < threshold - 15) {
      currentDecision = "ALLOW";
    } else if (score < threshold) {
      currentDecision = "STEP-UP AUTH REQUIRED";
    } else {
      currentDecision = "FLAGGED";
    }

    feedbackApplied = false;

    render(score, currentDecision, factors);
    updateFeedbackButtons();

    log(`AI model analyzed: "${aiResult.sessionText}"`);
    log(`Similarity to safe patterns: ${aiResult.safeSimilarity}`);
    log(`Similarity to risky patterns: ${aiResult.riskySimilarity}`);
    log(`Model output: ${aiResult.modelLabel}`);
    log(`Explicit anomaly score: ${aiResult.anomalyScore}`);
    log(`AI semantic adjustment: ${aiResult.aiAdjustment >= 0 ? "+" : ""}${aiResult.aiAdjustment}`);
    log(`Telemetry variation: ${aiResult.variation >= 0 ? "+" : ""}${aiResult.variation}`);
    log(`Behavioral risk analysis completed → ${currentDecision} (Score: ${score})`);
  } catch (error) {
    console.error(error);
    log("Error: session analysis failed.");
  } finally {
    scanStatus.textContent = "Entry approval complete";
    btnEvaluate.disabled = false;
  }
};

btnFalsePositive.onclick = () => {
  if (feedbackApplied || currentDecision !== "FLAGGED") return;

  const oldThreshold = threshold;
  falsePositives++;
  threshold = Math.min(90, threshold + 5);
  feedbackApplied = true;

  updateModelStatus();
  thresholdEl.textContent = threshold;
  prevThresholdEl.textContent = oldThreshold;
  thresholdChangeEl.textContent = `False positive feedback raised threshold from ${oldThreshold} to ${threshold}.`;
  updateFeedbackButtons();

  log(`False positive detected → threshold changed from ${oldThreshold} to ${threshold}`);
};

btnThreat.onclick = () => {
  if (feedbackApplied || currentDecision !== "FLAGGED") return;

  const oldThreshold = threshold;
  confirmedThreats++;
  threshold = Math.max(40, threshold - 5);
  feedbackApplied = true;

  updateModelStatus();
  thresholdEl.textContent = threshold;
  prevThresholdEl.textContent = oldThreshold;
  thresholdChangeEl.textContent = `Confirmed threat feedback lowered threshold from ${oldThreshold} to ${threshold}.`;
  updateFeedbackButtons();

  log(`Threat confirmed → threshold changed from ${oldThreshold} to ${threshold}`);
};

btnReset.onclick = () => {
  scanned = false;
  feedbackApplied = false;
  currentDecision = "";

  scanStatus.textContent = extractor
    ? "AI model loaded. Ready for entry approval."
    : "Loading AI model...";

  btnEvaluate.disabled = true;
  disableFeedbackButtons();

  riskScoreEl.textContent = "—";
  decisionEl.textContent = "—";
  decisionEl.className = "";
  factorsEl.innerHTML = "";
  prevThresholdEl.textContent = "—";
  thresholdChangeEl.textContent = "No feedback applied yet.";

  if (aiOutputEl) {
    aiOutputEl.textContent = "";
  }

  resetTypingCapture();
  detectLoginTime();
  detectDeviceFamiliarity();

  log("System reset.");
};

// INIT
targetPhraseEl.textContent = targetPhrase;
thresholdEl.textContent = threshold;
updateModelStatus();
disableFeedbackButtons();
detectLoginTime();
detectDeviceFamiliarity();
resetTypingCapture();
loadModel();
log("Prototype ready.");