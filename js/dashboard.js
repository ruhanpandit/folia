// ══════════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════════
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.ntab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}

function showChart(id, btn) {
  document.querySelectorAll('.cpanel,.cpanel-bar').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.ctab').forEach(t => t.classList.remove('active'));
  document.getElementById('cpanel-' + id).classList.add('active');
  btn.classList.add('active');
  if (id === 'perf' && charts.perf) charts.perf.resize();
  if (id === 'day'  && charts.day)  charts.day.resize();
}

// ══════════════════════════════════════════════
//  RENDER DASHBOARD
// ══════════════════════════════════════════════

/**
 * OWASP A03 — XSS note
 * All OCR-derived strings (ticker symbols, company names, sector names) are
 * wrapped in esc() before being interpolated into innerHTML template literals.
 * Numeric outputs from fmt() / fmtPct() are safe by construction (digits,
 * commas, dots, $, %, +/- only) but are still escaped for defence in depth.
 */
function renderDashboard() {
  const D = portfolioData;

  const dayClass = D.totalDayChange >= 0 ? 'pos' : 'neg';
  const plClass  = D.totalGainLoss  >= 0 ? 'pos' : 'neg';

  // Stat cards — no OCR text here, only formatted numbers; safe.
  document.getElementById('statsRow').innerHTML = `
    <div class="scard cb"><div class="scard-bg">💼</div>
      <div class="slabel">Total Portfolio Value</div>
      <div class="sval">${esc(fmt(D.totalValue))}</div>
      <div class="ssub">${D.holdings.length} position${D.holdings.length !== 1 ? 's' : ''} + cash</div></div>
    <div class="scard cg"><div class="scard-bg">📊</div>
      <div class="slabel">Total P&L</div>
      <div class="sval ${plClass}">${D.totalGainLoss >= 0 ? '+' : ''}${esc(fmt(D.totalGainLoss))}</div>
      <div class="ssub ${plClass}">${esc(fmtPct(D.totalGainLossPct))} overall return</div></div>
    <div class="scard cp"><div class="scard-bg">📅</div>
      <div class="slabel">Day Change</div>
      <div class="sval ${dayClass}">${D.totalDayChange >= 0 ? '+' : ''}${esc(fmt(D.totalDayChange))}</div>
      <div class="ssub ${dayClass}">${esc(fmtPct(D.totalDayPct))} today</div></div>
    <div class="scard cy"><div class="scard-bg">💵</div>
      <div class="slabel">Buying Power</div>
      <div class="sval">${esc(fmt(D.cash))}</div>
      <div class="ssub">Cash &amp; money market</div></div>
  `;

  // Holdings table — symbol and name come from OCR; must be escaped.
  const tbody  = document.getElementById('holdingsTbody');
  const maxVal = Math.max(...D.holdings.map(h => h.marketValue));
  tbody.innerHTML = D.holdings.map(h => {
    const wPct = (h.marketValue / D.totalValue * 100).toFixed(1);
    const wBar = (h.marketValue / maxVal * 100).toFixed(1);
    const glC  = h.gainLoss  >= 0 ? 'pos' : 'neg';
    const dayC = h.dayChange >= 0 ? 'pos' : 'neg';
    return `<tr>
      <td><div class="sym">${esc(h.symbol)}</div><div class="coname">${esc(h.name)}</div></td>
      <td>${esc(String(h.quantity || '—'))}</td>
      <td>${h.price ? esc(fmt(h.price)) : '—'}</td>
      <td>${esc(fmt(h.marketValue))}</td>
      <td><div class="wbar-wrap">
        <div class="wbar-bg"><div class="wbar-fill" style="width:${wBar}%;background:${h.color};"></div></div>
        <span>${wPct}%</span></div></td>
      <td class="${dayC}">${h.dayChange >= 0 ? '+' : ''}${esc(fmt(h.dayChange))}</td>
      <td class="${glC}">${h.gainLoss  >= 0 ? '+' : ''}${esc(fmt(h.gainLoss))}</td>
      <td class="${glC}">${esc(fmtPct(h.gainLossPct))}</td>
    </tr>`;
  }).join('');

  // Sector bars — sector names come from the SECTOR_COLORS whitelist; still escaped.
  const sectors = D.sectors;
  const sKeys   = Object.keys(sectors).sort((a, b) => sectors[b].val - sectors[a].val);
  const maxSec  = sectors[sKeys[0]].val;
  document.getElementById('sectorBars').innerHTML = sKeys.map(k => `
    <div class="sb-row">
      <span class="sb-name">${esc(k)}</span>
      <div class="sb-bg"><div class="sb-fill" style="width:${(sectors[k].val / maxSec * 100).toFixed(1)}%;background:${sectors[k].col || '#475569'};"></div></div>
      <span class="sb-pct">${(sectors[k].val / D.totalValue * 100).toFixed(1)}%</span>
    </div>`).join('');

  // textContent is safe by definition — no escaping needed here.
  document.getElementById('donutVal').textContent    = '$' + Math.round(D.totalValue).toLocaleString();
  document.getElementById('sectorCount').textContent = sKeys.length;

  initCharts();
}

// ══════════════════════════════════════════════
//  CHARTS
// ══════════════════════════════════════════════
function initCharts() {
  Chart.defaults.color       = '#64748b';
  Chart.defaults.borderColor = '#1f2d47';
  const D = portfolioData;

  const donutOpts = {
    responsive: false, cutout: '68%',
    plugins: {
      legend: { display: false },
      // Chart.js renders tooltip text as plain text, not HTML — safe without escaping.
      tooltip: { callbacks: { label: c => ` ${fmt(c.parsed)} (${(c.parsed / D.totalValue * 100).toFixed(1)}%)` }}
    },
    animation: { duration: 700 }
  };

  // Allocation donut
  if (charts.alloc) charts.alloc.destroy();
  charts.alloc = new Chart(document.getElementById('allocChart'), {
    type: 'doughnut',
    data: {
      // Chart.js labels are rendered as canvas text, not HTML — safe.
      labels: D.holdings.map(h => h.symbol),
      datasets: [{ data: D.holdings.map(h => h.marketValue), backgroundColor: D.holdings.map(h => h.color),
                   borderColor: '#080c18', borderWidth: 3, hoverOffset: 10 }]
    },
    options: donutOpts
  });

  // Allocation legend — OCR-derived symbol and name go into innerHTML, so escape them.
  const al = document.getElementById('allocLegend');
  al.innerHTML = D.holdings.map(h => {
    const pct = (h.marketValue / D.totalValue * 100).toFixed(1);
    return `<div class="leg-item">
      <div class="leg-left"><div class="leg-swatch" style="background:${h.color}"></div>
        <div><div class="leg-sym">${esc(h.symbol)}</div><div class="leg-name">${esc(h.name)}</div></div></div>
      <div class="leg-right"><div class="leg-val">${esc(fmt(h.marketValue))}</div><div class="leg-pct">${pct}%</div></div>
    </div>`;
  }).join('');

  // Sector donut
  if (charts.sector) charts.sector.destroy();
  const sk = Object.keys(D.sectors);
  charts.sector = new Chart(document.getElementById('sectorChart'), {
    type: 'doughnut',
    data: {
      labels: sk,  // canvas text — safe
      datasets: [{ data: sk.map(k => D.sectors[k].val),
                   backgroundColor: sk.map(k => D.sectors[k].col || '#475569'),
                   borderColor: '#080c18', borderWidth: 3, hoverOffset: 10 }]
    },
    options: donutOpts
  });

  // Sector legend — sector names into innerHTML, so escape.
  const sl = document.getElementById('sectorLegend');
  sl.innerHTML = sk.sort((a, b) => D.sectors[b].val - D.sectors[a].val).map(k => {
    const pct = (D.sectors[k].val / D.totalValue * 100).toFixed(1);
    return `<div class="leg-item">
      <div class="leg-left"><div class="leg-swatch" style="background:${D.sectors[k].col || '#475569'}"></div>
        <div><div class="leg-sym">${esc(k)}</div><div class="leg-name">${pct}% of portfolio</div></div></div>
      <div class="leg-right"><div class="leg-val">${esc(fmt(D.sectors[k].val))}</div><div class="leg-pct">${pct}%</div></div>
    </div>`;
  }).join('');

  const barOpts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => ` ${fmt(c.parsed.y)}` }}},
    scales: {
      x: { grid: { color: 'rgba(31,45,71,.6)' }, ticks: { color: '#64748b' }},
      y: { grid: { color: 'rgba(31,45,71,.6)' }, ticks: { color: '#64748b', callback: v => `$${v}` }}
    },
    animation: { duration: 600 }
  };

  // P&L bar — labels are canvas text, not HTML; safe.
  if (charts.perf) charts.perf.destroy();
  charts.perf = new Chart(document.getElementById('perfChart'), {
    type: 'bar',
    data: {
      labels: D.holdings.map(h => h.symbol),
      datasets: [{ label: 'P&L ($)', data: D.holdings.map(h => h.gainLoss),
        backgroundColor: D.holdings.map(h => h.gainLoss >= 0 ? 'rgba(16,185,129,.65)' : 'rgba(239,68,68,.65)'),
        borderColor:     D.holdings.map(h => h.gainLoss >= 0 ? '#10b981' : '#ef4444'),
        borderWidth: 1, borderRadius: 6 }]
    },
    options: barOpts
  });

  // Day change bar
  if (charts.day) charts.day.destroy();
  charts.day = new Chart(document.getElementById('dayChart'), {
    type: 'bar',
    data: {
      labels: D.holdings.map(h => h.symbol),
      datasets: [{ label: 'Day Change ($)', data: D.holdings.map(h => h.dayChange),
        backgroundColor: D.holdings.map(h => h.dayChange >= 0 ? 'rgba(59,130,246,.65)' : 'rgba(239,68,68,.65)'),
        borderColor:     D.holdings.map(h => h.dayChange >= 0 ? '#3b82f6' : '#ef4444'),
        borderWidth: 1, borderRadius: 6 }]
    },
    options: barOpts
  });
}
