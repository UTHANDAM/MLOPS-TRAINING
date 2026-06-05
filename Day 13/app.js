// ─── API Configuration ────────────────────────────────────────────────
    const isFileOpen = window.location.protocol === "file:";
    const isLiveServer = window.location.port && window.location.port !== "5000";
    const API_BASE = (isFileOpen || isLiveServer) ? "http://127.0.0.1:5000" : "";

    let defaults = {};
    let options = {};
    let isSubmitting = false;
    let lastPredictionResult = null;

    // ─── Particle Canvas ──────────────────────────────────────────────────
    (function initParticles() {
      const canvas = document.getElementById('particleCanvas');
      const ctx = canvas.getContext('2d');
      let particles = [];
      let w, h;

      function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
      }

      function createParticles() {
        particles = [];
        const count = Math.min(Math.floor((w * h) / 18000), 80);
        for (let i = 0; i < count; i++) {
          particles.push({
            x: Math.random() * w,
            y: Math.random() * h,
            vx: (Math.random() - 0.5) * 0.3,
            vy: (Math.random() - 0.5) * 0.3,
            r: Math.random() * 1.5 + 0.5,
            opacity: Math.random() * 0.4 + 0.1,
          });
        }
      }

      function draw() {
        ctx.clearRect(0, 0, w, h);
        for (const p of particles) {
          p.x += p.vx;
          p.y += p.vy;
          if (p.x < 0) p.x = w;
          if (p.x > w) p.x = 0;
          if (p.y < 0) p.y = h;
          if (p.y > h) p.y = 0;

          ctx.beginPath();
          ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(0, 229, 200, ${p.opacity})`;
          ctx.fill();
        }

        // Draw connections
        for (let i = 0; i < particles.length; i++) {
          for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 150) {
              ctx.beginPath();
              ctx.moveTo(particles[i].x, particles[i].y);
              ctx.lineTo(particles[j].x, particles[j].y);
              ctx.strokeStyle = `rgba(0, 229, 200, ${0.04 * (1 - dist / 150)})`;
              ctx.lineWidth = 0.5;
              ctx.stroke();
            }
          }
        }

        requestAnimationFrame(draw);
      }

      window.addEventListener('resize', () => { resize(); createParticles(); });
      resize();
      createParticles();
      draw();
    })();

    // ─── View Router ──────────────────────────────────────────────────────
    function route() {
      const hash = window.location.hash;
      const navToggle = document.getElementById('navToggle');
      const isWorkspace = hash === '#workspace';

      document.getElementById('landingView').classList.toggle('hidden', isWorkspace);
      document.getElementById('workspaceView').classList.toggle('hidden', !isWorkspace);

      if (navToggle) {
        if (isWorkspace) {
          navToggle.href = '#';
          navToggle.querySelector('span').textContent = 'Back to Overview';
        } else {
          navToggle.href = '#workspace';
          navToggle.querySelector('span').textContent = 'Open Workspace';
        }
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // ─── Scroll Reveal (IntersectionObserver) ─────────────────────────────
    function initReveal() {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add('visible');
          }
        });
      }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

      document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
    }

    // ─── Form Utilities ───────────────────────────────────────────────────
    function optionElement(value, selectedValue) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = value;
      if (String(value) === String(selectedValue)) option.selected = true;
      return option;
    }

    function fillSelect(id, values, selectedValue) {
      const select = document.getElementById(id);
      if (!select) return;
      select.innerHTML = '';
      values.forEach(v => select.appendChild(optionElement(v, selectedValue)));
    }

    // ─── API: Health Status ───────────────────────────────────────────────
    function checkAPIStatus() {
      const badge = document.getElementById('apiStatusBadge');
      if (!badge) return;

      fetch(`${API_BASE}/health`)
        .then(r => r.json())
        .then(data => {
          if (data.status === 'ok') {
            badge.classList.remove('offline');
            badge.classList.add('online');
            badge.querySelector('.status-text').textContent = 'API Online';
          }
        })
        .catch(() => {
          badge.classList.remove('online');
          badge.classList.add('offline');
          badge.querySelector('.status-text').textContent = 'API Offline';
        });
    }

    // ─── API: Load Options ────────────────────────────────────────────────
    function loadOptions() {
      return fetch(`${API_BASE}/get_form_options`)
        .then(r => r.json())
        .then(data => {
          defaults = data.defaults || {};
          options = data.options || {};

          Object.keys(options).forEach(field => {
            fillSelect(field, options[field], defaults[field]);
          });

          Object.keys(defaults).forEach(field => {
            const el = document.getElementById(field);
            if (el && el.tagName !== 'SELECT') el.value = defaults[field];
          });
        });
    }

    // ─── API: Model Metadata ──────────────────────────────────────────────
    function loadModelMetadata() {
      const badge = document.getElementById('modelBadge');
      if (!badge) return;

      fetch(`${API_BASE}/get_model_metadata`)
        .then(r => r.json())
        .then(meta => {
          badge.textContent = meta.model_name || 'Claims Analyzer';
        })
        .catch(() => {
          badge.textContent = 'Claims Analyzer';
        });
    }

    // ─── Build Payload ────────────────────────────────────────────────────
    function formToPayload() {
      const form = document.getElementById('riskForm');
      const fd = new FormData(form);
      const payload = {};
      for (const [k, v] of fd.entries()) payload[k] = v;
      return payload;
    }

    // ─── Gauge Animation ──────────────────────────────────────────────────
    function animateGauge(riskScore) {
      const fill = document.getElementById('gaugeFill');
      const display = document.getElementById('gaugeScoreValue');
      if (!fill || !display) return;

      const offset = 283 - (riskScore * 283);
      fill.style.strokeDashoffset = offset;

      if (riskScore < 0.35) {
        fill.style.stroke = 'var(--success)';
      } else if (riskScore < 0.70) {
        fill.style.stroke = 'var(--warning)';
      } else {
        fill.style.stroke = 'var(--danger)';
      }

      // Count up
      let current = 0;
      const target = Math.round(riskScore * 100);
      const step = target / 75;
      const counter = setInterval(() => {
        current += step;
        if (current >= target) {
          display.textContent = `${target}%`;
          clearInterval(counter);
        } else {
          display.textContent = `${Math.round(current)}%`;
        }
      }, 16);
    }

    // ─── Render Result ────────────────────────────────────────────────────
    function renderResult(result) {
      lastPredictionResult = result;

      const empty = document.getElementById('resultState');
      const card = document.getElementById('resultCard');
      const verdict = document.getElementById('riskVerdictBadge');
      const recBox = document.getElementById('recommendationBox');

      if (empty) empty.classList.add('hidden');
      if (card) card.classList.remove('hidden');

      const isHigh = result.prediction === 1;

      if (verdict) {
        verdict.textContent = result.risk_label;
        verdict.className = 'verdict-badge ' + (isHigh ? 'high' : 'low');
      }

      if (recBox) {
        recBox.className = 'rec-box' + (isHigh ? ' high' : '');
        recBox.querySelector('.rec-text').textContent = result.recommendation;
      }

      document.getElementById('valPrediction').textContent = result.prediction === 1 ? 'Suspicious' : 'Genuine';
      
      let rLevel = 'Low';
      if (result.prediction === 1) rLevel = 'High';
      else if (result.risk_label.includes('Moderate')) rLevel = 'Moderate';
      document.getElementById('valRiskLevel').textContent = rLevel;
      
      document.getElementById('valDeductible').textContent = result.input_used && result.input_used.Deductible ? `$${result.input_used.Deductible}` : '-';

      const score = result.risk_score !== null && result.risk_score !== undefined
        ? Number(result.risk_score)
        : (isHigh ? 0.94 : 0.05);

      animateGauge(score);
    }

    // ─── Predict ──────────────────────────────────────────────────────────
    function predictClaimRisk(event) {
      event.preventDefault();
      if (isSubmitting) return;

      const btn = document.getElementById('submitBtn');
      const empty = document.getElementById('resultState');
      const card = document.getElementById('resultCard');

      isSubmitting = true;
      if (btn) { btn.classList.add('loading'); btn.disabled = true; }

      if (empty) {
        empty.classList.remove('hidden');
        empty.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="pulse-loader" style="width:40px;height:40px;color:var(--accent-primary)">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          <p class="pulse-loader">Evaluating claim signals…</p>
        `;
      }
      if (card) card.classList.add('hidden');

      fetch(`${API_BASE}/predict_claim_risk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formToPayload()),
      })
        .then(r => r.json())
        .then(data => renderResult(data))
        .catch(err => {
          if (empty) {
            empty.innerHTML = `
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:40px;height:40px;color:var(--danger)">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <p style="color:var(--danger)">Prediction failed: ${err.message || err}</p>
            `;
          }
        })
        .finally(() => {
          isSubmitting = false;
          if (btn) { btn.classList.remove('loading'); btn.disabled = false; }
        });
    }

    // ─── Reset ────────────────────────────────────────────────────────────
    function resetForm() {
      Object.keys(defaults).forEach(field => {
        const el = document.getElementById(field);
        if (el) el.value = defaults[field];
      });

      const empty = document.getElementById('resultState');
      const card = document.getElementById('resultCard');
      const gaugeFill = document.getElementById('gaugeFill');

      if (empty) {
        empty.classList.remove('hidden');
        empty.innerHTML = `
          <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="width:44px;height:44px;color:var(--text-dim)">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
          <p>Configure the claim profile inputs and analyze risk score details.</p>
        `;
      }
      if (card) card.classList.add('hidden');
      if (gaugeFill) gaugeFill.style.strokeDashoffset = 283;
      lastPredictionResult = null;
    }

    // ─── Export Report ────────────────────────────────────────────────────
    function exportSummaryReport() {
      if (!lastPredictionResult) return;

      const claim = lastPredictionResult.input_used || {};
      let c = "══════════════════════════════════════════════════\n";
      c += "          RISKPROOF AI CLAIM REVIEW REPORT         \n";
      c += "══════════════════════════════════════════════════\n\n";
      c += `Report Type: Claims Risk Assessment Report\n`;
      c += `Prediction Verdict: ${lastPredictionResult.risk_label}\n`;
      c += `Risk Score: ${lastPredictionResult.risk_score ? (Number(lastPredictionResult.risk_score) * 100).toFixed(1) : 'N/A'}%\n\n`;
      c += "── BROKER RECOMMENDATION ──\n";
      c += `${lastPredictionResult.recommendation}\n\n`;
      c += "── SUBMITTED CLAIM PROFILE ──\n";
      Object.keys(claim).forEach(k => { c += `${k}: ${claim[k]}\n`; });
      c += "\n══════════════════════════════════════════════════\n";
      c += "Generated by RiskProof AI | Sri Shakthi Institute of Engineering & Technology\n";

      const blob = new Blob([c], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `RiskProof_Claim_Report_${Date.now()}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    // ─── Init ─────────────────────────────────────────────────────────────
    window.addEventListener('DOMContentLoaded', () => {
      // Routing
      window.addEventListener('hashchange', route);
      route();

      // API
      loadOptions().catch(err => console.error('Error loading options:', err));
      loadModelMetadata();
      checkAPIStatus();
      setInterval(checkAPIStatus, 10000);

      // Accordion toggles
      document.querySelectorAll('.accordion-trigger').forEach(trigger => {
        trigger.addEventListener('click', () => {
          const card = trigger.closest('.accordion-card');
          if (card) card.classList.toggle('expanded');
        });
      });

      // Form
      const form = document.getElementById('riskForm');
      if (form) form.addEventListener('submit', predictClaimRisk);

      const resetBtn = document.getElementById('resetBtn');
      if (resetBtn) resetBtn.addEventListener('click', resetForm);

      const exportBtn = document.getElementById('exportBtn');
      if (exportBtn) exportBtn.addEventListener('click', exportSummaryReport);

      // Reveal on scroll
      initReveal();
    });