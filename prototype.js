// Working prototype: lightweight "AI-like" scoring model that adapts via user feedback.
// This is intentionally simple but demonstrable and measurable for SIP requirements.

const btnScan = document.getElementById("btnScan");
const btnEvaluate = document.getElementById("btnEvaluate");
const btnFalsePositive = document.getElementById("btnFalsePositive");
const btnReset = document.getElementById("btnReset");

const scanStatus = document.getElementById("scanStatus");
const loginTime = document.getElementById("loginTime");
const device = document.getElementById("device");
const locationSel = document.getElementById("location");

const riskScoreEl = document.getElementById("riskScore");
const decisionEl = document.getElementById("decision");
const thresholdEl = document.getElementById("threshold");
const logEl = document.getElementById("log");

// Threshold represents "model sensitivity".
// Higher threshold = fewer flags (less sensitive), lower threshold = more flags (more sensitive).
let threshold = 60;

// Store last evaluation so we can adjust based on false positive feedback
let lastRiskScore = null;
let lastDecision = null;
let scanned = false;

function addLog(message) {
  const li = document.createElement("li");
  const stamp = new Date().toLocaleTimeString();
  li.textContent = `[${stamp}] ${message}`;
  logEl.prepend(li);
}

function computeRiskScore() {
  let score = 0;

  // Risk weights (simple + explainable)
  if (loginTime.value === "late") score += 35;
  if (device.value === "new") score += 35;
  if (locationSel.value === "unusual") score += 35;

  // Small baseline noise for realism (0–5)
  score += Math.floor(Math.random() * 6);

  return Math.min(100, score);
}

function renderResult(score, decision) {
  riskScoreEl.textContent = `${score}/100`;
  decisionEl.textContent = decision;
  thresholdEl.textContent = `${threshold}/100`;
}

function resetUI() {
  scanned = false;
  lastRiskScore = null;
  lastDecision = null;

  scanStatus.textContent = "Waiting for scan…";
  btnEvaluate.disabled = true;
  btnFalsePositive.disabled = true;

  riskScoreEl.textContent = "—";
  decisionEl.textContent = "—";
  thresholdEl.textContent = `${threshold}/100`;

  addLog("Prototype reset.");
}

btnScan.addEventListener("click", () => {
  scanned = true;
  scanStatus.textContent = "Biometric scan complete. Ready to evaluate session.";
  btnEvaluate.disabled = false;
  addLog("Biometric scan simulated successfully.");
});

btnEvaluate.addEventListener("click", () => {
  if (!scanned) return;

  const score = computeRiskScore();
  const decision = score >= threshold ? "FLAGGED: Suspicious Session" : "ALLOWED: Session Granted";

  lastRiskScore = score;
  lastDecision = decision;

  renderResult(score, decision);

  // Only enable false-positive if the system flagged it
  btnFalsePositive.disabled = !(decision.startsWith("FLAGGED"));

  addLog(
    `Session evaluated. Inputs: time=${loginTime.value}, device=${device.value}, location=${locationSel.value}. Score=${score}. Decision=${decision}.`
  );
});

btnFalsePositive.addEventListener("click", () => {
  if (!lastDecision || !lastDecision.startsWith("FLAGGED")) return;

  // Adaptive change: raise threshold slightly so similar sessions are less likely to be flagged.
  // This simulates learning from user feedback to reduce false positives.
  const oldThreshold = threshold;
  threshold = Math.min(90, threshold + 7);

  addLog(`False positive marked by user. Threshold adjusted from ${oldThreshold} to ${threshold} (reduced sensitivity).`);
  renderResult(lastRiskScore, lastDecision + " (Marked False Positive)");
  btnFalsePositive.disabled = true;
});

btnReset.addEventListener("click", resetUI);

// Initialize
thresholdEl.textContent = `${threshold}/100`;
addLog("Prototype loaded. Ready for biometric scan.");