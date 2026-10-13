// Statistics charts (Chart.js 4, vendored). No inline script: CSP script-src 'self'.
"use strict";
(function () {
  const root = document.getElementById("stats");
  if (!root || typeof Chart === "undefined") return;
  const css = getComputedStyle(document.documentElement);
  const v = (name) => css.getPropertyValue(name).trim();

  function bars(canvasId, labels, values, label) {
    const ctx = document.getElementById(canvasId);
    return new Chart(ctx, {
      type: "bar",
      data: { labels, datasets: [{ label, data: values, backgroundColor: v("--series-1"),
                                   borderRadius: 4, borderSkipped: "bottom", maxBarThickness: 24 }] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false } },        // single series: the card title names it
        scales: {
          x: { grid: { display: false }, ticks: { color: v("--text-secondary"), maxRotation: 0, autoSkip: true } },
          y: { beginAtZero: true, grid: { color: v("--grid") }, border: { display: false },
               ticks: { color: v("--text-secondary"), precision: 0 } },
        },
      },
    });
  }

  function cell(row, text) {
    const td = document.createElement("td");
    td.textContent = text;                               // textContent only: never HTML from data
    row.appendChild(td);
  }

  fetch(root.dataset.endpoint, { credentials: "same-origin", headers: { Accept: "application/json" } })
    .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then((data) => {
      const days = data.per_day.map((d) => d.day);
      bars("scans-chart", days, data.per_day.map((d) => d.scans), "Scans");
      bars("threats-chart", days, data.per_day.map((d) => d.threats), "Detections");
      const top = document.getElementById("top-signatures");
      top.replaceChildren();
      for (const s of data.top_signatures) {
        const li = document.createElement("li");
        li.textContent = s.signature + " — " + s.count;
        top.appendChild(li);
      }
      if (!data.top_signatures.length) {
        const li = document.createElement("li"); li.textContent = "No detections."; top.appendChild(li);
      }
      const body = document.getElementById("stats-table-body");
      for (const d of data.per_day) {
        const tr = document.createElement("tr");
        cell(tr, d.day); cell(tr, String(d.scans)); cell(tr, String(d.threats));
        cell(tr, Object.entries(d.verdicts).map(([k, n]) => k + " " + n).join(", "));
        body.appendChild(tr);
      }
    })
    .catch(() => {
      const top = document.getElementById("top-signatures");
      top.replaceChildren();
      const li = document.createElement("li"); li.textContent = "Statistics unavailable."; top.appendChild(li);
    });
})();
