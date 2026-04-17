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

const aiOutputEl = document.getElementById("aiOutput");

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
    parts.push("Login occurred outside normal access hours.");
  } else {
    parts.push("Login occurred during expected access hours.");
  }

  if (device.value === "new") {
    parts.push("Device is new and not previously recognized.");
  } else {
    parts.push("Device is known and previously trusted.");
  }

  if (locationSel.value === "unusual") {
    parts.push("Location is unusual compared to prior user activity.");
  } else {
    parts.push("Location matches the user's normal access area.");
  }

  if (typing.value === "weird") {
    parts.push("Typing behavior is inconsistent with the normal user profile.");
  } else {
    parts.push("Typing behavior matches the user's normal profile.");
  }

  return parts.join(" ");
}

// EXPLANATION LIST FOR THE UI
function buildFactors() {
  const factors = [];

  if (loginTime.value === "late") factors.push("Late night login detected");
  if (device.value === "new") factors.push("New or unrecognized device");
  if (locationSel.value === "unusual") factors.push("Login from unusual location");
  if (typing.value === "weird") factors.push("Typing pattern anomaly detected");

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

  // Small variation so repeated runs are not identical
  let variation = 0;
  if (anomalyScore === 0) {
    variation = Math.floor(Math.random() * 4); // 0 to 3
  } else if (anomalyScore >= 80) {
    variation = Math.floor(Math.random() * 5) - 2; // -2 to +2
  } else {
    variation = Math.floor(Math.random() * 7) - 3; // -3 to +3
  }

  const finalScore = Math.max(
    0,
    Math.min(100, anomalyScore + aiAdjustment + variation)
  );

  // Make the model label track the practical result range
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

  if (aiOutputEl) {
    aiOutputEl.textContent = "";
  }

  log("System reset.");
};

// INIT
thresholdEl.textContent = threshold;
updateModelStatus();
disableFeedbackButtons();
loadModel();
log("Prototype ready.");