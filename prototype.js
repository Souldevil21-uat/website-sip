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

let threshold = 60;
let scanned = false;
let lastScore = null;
let lastDecision = null;

function log(message) {
  const li = document.createElement("li");
  li.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.prepend(li);
}

function computeRisk() {
  let score = 0;
  let factors = [];

  if (loginTime.value === "late") {
    score += 30;
    factors.push("Late night login detected");
  }

  if (device.value === "new") {
    score += 30;
    factors.push("New or unrecognized device");
  }

  if (locationSel.value === "unusual") {
    score += 30;
    factors.push("Login from unusual location");
  }

  if (typing.value === "weird") {
    score += 20;
    factors.push("Typing pattern anomaly detected");
  }

  score += Math.floor(Math.random() * 6);

  if (factors.length === 0) {
    factors.push("All behavioral signals fall within normal thresholds.");
  }

  return {
    score: Math.min(score, 100),
    factors: factors
  };
}

function render(score, decision, factors) {
  riskScoreEl.textContent = score;
  decisionEl.textContent = decision;
  thresholdEl.textContent = threshold;

  factorsEl.innerHTML = "";

  factors.forEach(factor => {
    const li = document.createElement("li");
    li.textContent = factor;
    factorsEl.appendChild(li);
  });
}

btnScan.onclick = () => {
  scanned = true;
  scanStatus.textContent = "Biometric scan complete";
  btnEvaluate.disabled = false;
  log("Biometric scan successful");
};

btnEvaluate.onclick = () => {
  if (!scanned) return;

  const result = computeRisk();
  const score = result.score;
  const factors = result.factors;

  let decision = "";

  if (score < threshold - 15) {
    decision = "ALLOW";
  } else if (score < threshold) {
    decision = "STEP-UP AUTH REQUIRED";
  } else {
    decision = "FLAGGED";
  }

  lastScore = score;
  lastDecision = decision;

  render(score, decision, factors);

  btnFalsePositive.disabled = decision !== "FLAGGED";
  btnThreat.disabled = decision !== "FLAGGED";

  log(`Session evaluated: ${decision} (Score ${score})`);
};

btnFalsePositive.onclick = () => {
  threshold = Math.min(90, threshold + 5);
  log("False positive → system less sensitive");
  btnFalsePositive.disabled = true;
};

btnThreat.onclick = () => {
  threshold = Math.max(40, threshold - 5);
  log("Threat confirmed → system more sensitive");
  btnThreat.disabled = true;
};

btnReset.onclick = () => {
  scanned = false;
  lastScore = null;
  lastDecision = null;

  scanStatus.textContent = "Waiting for scan...";
  btnEvaluate.disabled = true;
  btnFalsePositive.disabled = true;
  btnThreat.disabled = true;

  riskScoreEl.textContent = "—";
  decisionEl.textContent = "—";
  factorsEl.innerHTML = "";

  log("System reset");
};

thresholdEl.textContent = threshold;
log("Prototype ready");