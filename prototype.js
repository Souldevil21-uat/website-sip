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

// LOG FUNCTION
function log(message) {
  const li = document.createElement("li");
  li.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.prepend(li);
}

// RISK MODEL
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

// RENDER RESULTS
function render(score, decision, factors) {
  riskScoreEl.textContent = score;
  thresholdEl.textContent = threshold;

  // COLOR DECISION
  decisionEl.className = "";
  if (decision === "ALLOW") {
    decisionEl.classList.add("allow");
  } else if (decision === "STEP-UP AUTH REQUIRED") {
    decisionEl.classList.add("stepup");
  } else {
    decisionEl.classList.add("flagged");
  }

  decisionEl.textContent = decision;

  // FACTORS
  factorsEl.innerHTML = "";
  factors.forEach(factor => {
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

// BUTTON EVENTS

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

  render(score, decision, factors);

// Always re-enable buttons on a new evaluation
if (decision === "FLAGGED") {
  btnFalsePositive.disabled = false;
  btnThreat.disabled = false;
} else {
  btnFalsePositive.disabled = true;
  btnThreat.disabled = true;
}

  log(`Behavioral risk analysis completed → ${decision} (Score: ${score})`);
};

btnFalsePositive.onclick = () => {
  threshold = Math.min(90, threshold + 5);
  falsePositives++;

  updateModelStatus();

  log("False positive detected → system sensitivity reduced");
  btnFalsePositive.disabled = true;
};

btnThreat.onclick = () => {
  threshold = Math.max(40, threshold - 5);
  confirmedThreats++;

  updateModelStatus();

  log(`Threat confirmed → system sensitivity increased (Total: ${confirmedThreats})`);
};

btnReset.onclick = () => {
  scanned = false;

  scanStatus.textContent = "Waiting for scan...";
  btnEvaluate.disabled = true;
  btnFalsePositive.disabled = true;
  btnThreat.disabled = true;

  riskScoreEl.textContent = "—";
  decisionEl.textContent = "—";
  decisionEl.className = "";
  factorsEl.innerHTML = "";

  log("System reset");
};

// INIT
thresholdEl.textContent = threshold;
updateModelStatus();
log("Prototype ready");