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
let classifier = null;

// LOG FUNCTION
function log(message) {
  const li = document.createElement("li");
  li.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.prepend(li);
}

// Build Session Text to Feed to the Model
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
    log("Loading real AI model for browser inference...");

    // Real model inference in the browser
    classifier = await pipeline(
  "zero-shot-classification",
  "Xenova/distilbert-base-uncased-mnli"
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

// Convert Model Output to AI Score
async function computeRiskWithAI() {
  const sessionText = buildSessionText();

  const output = await classifier(sessionText, [
    "normal account activity",
    "account takeover attempt"
  ], {
    hypothesis_template: "This authentication session is {}."
  });

  const suspiciousIndex = output.labels.findIndex(
    label => label.toLowerCase() === "account takeover attempt"
  );

  const suspiciousScore = suspiciousIndex >= 0
    ? output.scores[suspiciousIndex]
    : 0.5;

  const riskScore = Math.round(suspiciousScore * 100);

  return {
    score: riskScore,
    modelLabel: output.labels[0],
    modelConfidence: Math.round(output.scores[0] * 100),
    sessionText
  };
}

// Render Results
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

// Model Status
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

// Button Control
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

// Events
btnScan.onclick = () => {
  scanned = true;
  scanStatus.textContent = "Biometric scan complete";
  btnEvaluate.disabled = false;
  log("Biometric scan successful.");
};

btnEvaluate.onclick = async () => {
  if (!scanned || !classifier) return;

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
    log(`Model output: ${aiResult.modelLabel} (${aiResult.modelConfidence}% confidence)`);
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

  scanStatus.textContent = classifier
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