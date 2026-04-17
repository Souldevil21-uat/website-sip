import { pipeline } from "https://cdn.jsdelivr.net/npm/@huggingface/transformers@4.1.0";

// ELEMENTS
const btnScan = document.getElementById("btnScan");
const btnEvaluate = document.getElementById("btnEvaluate");
const btnFalsePositive = document.getElementById("btnFalsePositive");
const btnThreat = document.getElementById("btnThreat");
const btnReset = document.getElementById("btnReset");

const scanStatus = document.getElementById("scanStatus");

const loginTime = document.getElementById("loginTime");
const device = document.getElementById("device");
const locationSel = document.getElementById("location");
const typing = document.getElementById("typing");

const riskScoreEl = document.getElementById("riskScore");
const decisionEl = document.getElementById("decision");
const thresholdEl = document.getElementById("threshold");
const factorsEl = document.getElementById("factors");
const logEl = document.getElementById("log");

const fpCountEl = document.getElementById("fpCount");
const threatCountEl = document.getElementById("threatCount");
const sensitivityEl = document.getElementById("sensitivity");

// STATE
let threshold = 60;
let scanned = false;
let falsePositives = 0;
let confirmedThreats = 0;
let feedbackApplied = false;
let currentDecision = "";
let extractor = null;

// Reference examples for similarity comparison
const SAFE_EXAMPLES = [
  "Login during normal hours from a known device in the usual location with normal typing behavior.",
  "A recognized user accessed the account from a familiar device and expected location during normal business hours.",
  "Routine account activity from a trusted device in a normal location with behavior matching the user profile."
];

const RISKY_EXAMPLES = [
  "Late night login from a new device in an unusual location with abnormal typing behavior.",
  "Possible account takeover attempt using an unrecognized device, suspicious location, and behavior outside the user profile.",
  "Unusual authentication session with multiple anomalies including device mismatch, location mismatch, and inconsistent typing."
];

// LOG FUNCTION
function log(message) {
  const li = document.createElement("li");
  li.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.prepend(li);
}

// BUILD SESSION TEXT FOR THE MODEL
function buildSessionText() {
  const parts = [];

  if (loginTime.value === "late") {
    parts.push("The login happened late at night outside the user's normal access window.");
  } else {
    parts.push("The login happened during the user's normal access hours.");
  }

  if (device.value === "new") {
    parts.push("The session came from a new and previously unseen device.");
  } else {
    parts.push("The session came from a recognized device used before.");
  }

  if (locationSel.value === "unusual") {
    parts.push("The access location is unusual and does not match the normal user pattern.");
  } else {
    parts.push("The access location matches the user's usual area.");
  }

  if (typing.value === "weird") {
    parts.push("The typing behavior appears inconsistent with the user's normal pattern.");
  } else {
    parts.push("The typing behavior matches the user's normal pattern.");
  }

  return parts.join(" ");
}

// EXPLANATION LIST FOR THE UI
function buildFactors() {
  const factors = [];

  if (loginTime.value === "late") {
    factors.push("Late night login detected");
  }

  if (device.value === "new") {
    factors.push("New or unrecognized device");
  }

  if (locationSel.value === "unusual") {
    factors.push("Login from unusual location");
  }

  if (typing.value === "weird") {
    factors.push("Typing pattern anomaly detected");
  }

  if (factors.length === 0) {
    factors.push("All behavioral signals fall within normal thresholds.");
  }

  return factors;
}

// LOAD REAL AI MODEL
async function loadModel() {
  try {
    scanStatus.textContent = "Loading AI model...";
    log("Loading real AI embedding model for browser inference...");

    extractor = await pipeline(
      "feature-extraction",
      "Xenova/all-MiniLM-L6-v2"
    );

    scanStatus.textContent = "AI model loaded. Ready for biometric scan.";
    btnScan.disabled = false;
    log("AI model loaded successfully.");
  } catch (error) {
    console.error(error);
    scanStatus.textContent = "Failed to load AI model.";
    log("Error: AI model failed to load.");
  }
}

// GET NORMALIZED EMBEDDING
async function getEmbedding(text) {
  const output = await extractor(text, {
    pooling: "mean",
    normalize: true
  });

  // output.data is a Float32Array
  return Array.from(output.data);
}

// COSINE SIMILARITY
function cosineSimilarity(a, b) {
  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }

  if (magA === 0 || magB === 0) {
    return 0;
  }

  return dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

// AVERAGE SIMILARITY TO A SET OF EXAMPLES
async function averageSimilarity(sessionEmbedding, examples) {
  let total = 0;

  for (const example of examples) {
    const exampleEmbedding = await getEmbedding(example);
    total += cosineSimilarity(sessionEmbedding, exampleEmbedding);
  }

  return total / examples.length;
}

// COMPUTE RISK WITH REAL AI EMBEDDINGS
async function computeRiskWithAI() {
  const sessionText = buildSessionText();
  const sessionEmbedding = await getEmbedding(sessionText);

  const safeSimilarity = await averageSimilarity(sessionEmbedding, SAFE_EXAMPLES);
  const riskySimilarity = await averageSimilarity(sessionEmbedding, RISKY_EXAMPLES);

  // Main anomaly-driven score
  let anomalyScore = 0;

  if (loginTime.value === "late") anomalyScore += 20;
  if (device.value === "new") anomalyScore += 30;
  if (locationSel.value === "unusual") anomalyScore += 30;
  if (typing.value === "weird") anomalyScore += 20;

  // Real AI influence from semantic similarity
  const aiDelta = riskySimilarity - safeSimilarity;
  const aiAdjustment = Math.round(aiDelta * 15);

  // Slight but noticeable variation
  let variation = 0;

  if (anomalyScore === 0) {
    // Safe sessions: tiny range
    variation = Math.floor(Math.random() * 4); // 0 to 3
  } else if (anomalyScore >= 80) {
    // Very risky sessions: keep near the top
    variation = Math.floor(Math.random() * 5) - 2; // -2 to +2
  } else {
    // Mid-risk sessions: a little more movement
    variation = Math.floor(Math.random() * 7) - 3; // -3 to +3
  }

  const finalScore = Math.max(
    0,
    Math.min(100, anomalyScore + aiAdjustment + variation)
  );

  return {
    score: finalScore,
    anomalyScore: anomalyScore,
    aiAdjustment: aiAdjustment,
    variation: variation,
    modelLabel:
      riskySimilarity > safeSimilarity
        ? "RISKY PATTERN MATCH"
        : "SAFE PATTERN MATCH",
    sessionText,
    safeSimilarity: safeSimilarity.toFixed(3),
    riskySimilarity: riskySimilarity.toFixed(3)
  };
}

  return {
    score: finalScore,
    anomalyScore: anomalyScore,
    aiAdjustment: aiAdjustment,
    variation: variation,
    modelLabel:
      riskySimilarity > safeSimilarity
        ? "RISKY PATTERN MATCH"
        : "SAFE PATTERN MATCH",
    sessionText,
    safeSimilarity: safeSimilarity.toFixed(3),
    riskySimilarity: riskySimilarity.toFixed(3)
  };
}

// RENDER RESULTS
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

// MODEL STATUS
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

// BUTTON CONTROL
function disableFeedbackButtons() {
  btnFalsePositive.disabled = true;
  btnThreat.disabled = true;
}

function updateFeedbackButtons() {
  if (currentDecision === "FLAGGED" && feedbackApplied === false) {
    btnFalsePositive.disabled = false;
    btnThreat.disabled = false;
  } else {
    disableFeedbackButtons();
  }
}

// EVENTS
btnScan.onclick = () => {
  scanned = true;
  scanStatus.textContent = "Biometric scan complete";
  btnEvaluate.disabled = false;
  log("Biometric scan successful.");
};

btnEvaluate.onclick = async () => {
  if (!scanned || !extractor) return;

  btnEvaluate.disabled = true;
  scanStatus.textContent = "AI model analyzing session...";

  try {
    const aiResult = await computeRiskWithAI();
    const score = aiResult.score;
    const factors = buildFactors();

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
    scanStatus.textContent = "Biometric scan complete";
    btnEvaluate.disabled = false;
  }
};

btnFalsePositive.onclick = () => {
  if (feedbackApplied || currentDecision !== "FLAGGED") return;

  falsePositives++;
  threshold = Math.min(90, threshold + 5);
  feedbackApplied = true;

  updateModelStatus();
  thresholdEl.textContent = threshold;
  updateFeedbackButtons();

  log(`False positive detected → system sensitivity reduced (Total: ${falsePositives})`);
};

btnThreat.onclick = () => {
  if (feedbackApplied || currentDecision !== "FLAGGED") return;

  confirmedThreats++;
  threshold = Math.max(40, threshold - 5);
  feedbackApplied = true;

  updateModelStatus();
  thresholdEl.textContent = threshold;
  updateFeedbackButtons();

  log(`Threat confirmed → system sensitivity increased (Total: ${confirmedThreats})`);
};

btnReset.onclick = () => {
  scanned = false;
  feedbackApplied = false;
  currentDecision = "";

  scanStatus.textContent = extractor
    ? "AI model loaded. Ready for biometric scan."
    : "Loading AI model...";

  btnEvaluate.disabled = true;
  disableFeedbackButtons();

  riskScoreEl.textContent = "—";
  decisionEl.textContent = "—";
  decisionEl.className = "";
  factorsEl.innerHTML = "";

  log("System reset.");
};

// INIT
thresholdEl.textContent = threshold;
updateModelStatus();
disableFeedbackButtons();
loadModel();
log("Prototype ready.");