const isLocalStaticServer = ["127.0.0.1", "localhost"].includes(window.location.hostname)
  && window.location.port !== "5000";
const isFileOpen = window.location.protocol === "file:";
const API_BASE = isLocalStaticServer || isFileOpen ? "http://127.0.0.1:5000" : "/api";

let defaults = {};
let options = {};

function optionElement(value, selectedValue) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = value;
  if (String(value) === String(selectedValue)) {
    option.selected = true;
  }
  return option;
}

function fillSelect(id, values, selectedValue) {
  const select = document.getElementById(id);
  if (!select) return;
  select.innerHTML = "";
  values.forEach((value) => select.appendChild(optionElement(value, selectedValue)));
}

function loadOptions() {
  return fetch(`${API_BASE}/get_form_options`)
    .then((response) => response.json())
    .then((data) => {
      defaults = data.defaults || {};
      options = data.options || {};

      Object.keys(options).forEach((field) => {
        fillSelect(field, options[field], defaults[field]);
      });

      Object.keys(defaults).forEach((field) => {
        const element = document.getElementById(field);
        if (element && element.tagName !== "SELECT") {
          element.value = defaults[field];
        }
      });
    });
}

function loadModelMetadata() {
  const badge = document.getElementById("modelBadge");
  if (!badge) {
    return Promise.resolve();
  }

  return fetch(`${API_BASE}/get_model_metadata`)
    .then((response) => response.json())
    .then((metadata) => {
      const accuracy = metadata.best_accuracy ? `${(metadata.best_accuracy * 100).toFixed(2)}%` : "-";
      badge.textContent = `${metadata.model_name || "Model"} | ${accuracy}`;
    })
    .catch(() => {
      badge.textContent = "API offline";
    });
}

function formToPayload() {
  const form = document.getElementById("riskForm");
  const formData = new FormData(form);
  const payload = {};

  for (const [key, value] of formData.entries()) {
    payload[key] = value;
  }

  return payload;
}

function renderResult(result) {
  document.getElementById("resultState").classList.add("hidden");
  document.getElementById("resultCard").classList.remove("hidden");

  const riskRow = document.querySelector(".risk-row");
  riskRow.classList.toggle("high", result.prediction === 1);

  const score = result.risk_score === null || result.risk_score === undefined
    ? "-"
    : `${(Number(result.risk_score) * 100).toFixed(1)}%`;

  document.getElementById("riskLabel").textContent = result.risk_label;
  document.getElementById("riskScore").textContent = score;
  document.getElementById("predictionValue").textContent = result.prediction;
  document.getElementById("modelName").textContent = result.model_name;
  document.getElementById("bestAccuracy").textContent = `${(Number(result.best_accuracy) * 100).toFixed(2)}%`;
  document.getElementById("recommendation").textContent = result.recommendation;
}

function predictClaimRisk(event) {
  event.preventDefault();
  const payload = formToPayload();

  fetch(`${API_BASE}/predict_claim_risk`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
    .then((response) => response.json())
    .then(renderResult)
    .catch((error) => {
      document.getElementById("resultState").classList.remove("hidden");
      document.getElementById("resultCard").classList.add("hidden");
      document.getElementById("resultState").textContent = `Prediction failed: ${error}`;
    });
}

function resetForm() {
  Object.keys(defaults).forEach((field) => {
    const element = document.getElementById(field);
    if (element) {
      element.value = defaults[field];
    }
  });

  document.getElementById("resultState").classList.remove("hidden");
  document.getElementById("resultCard").classList.add("hidden");
  document.getElementById("resultState").textContent = "Enter claim details and run prediction.";
}

window.addEventListener("load", () => {
  loadOptions();
  loadModelMetadata();
  document.getElementById("riskForm").addEventListener("submit", predictClaimRisk);
  document.getElementById("resetBtn").addEventListener("click", resetForm);
});
