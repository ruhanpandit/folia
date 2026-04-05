// ══════════════════════════════════════════════
//  ANALYSIS
// ══════════════════════════════════════════════

/**
 * OWASP A03 — XSS note
 * Ticker symbols injected into innerHTML strings (buildStrengths, buildWeaknesses,
 * buildRecs) are wrapped in esc(). Even though the parser regex constrains symbols
 * to [A-Z]{2,5}, defence-in-depth requires escaping at the output boundary.
 *
 * OWASP A03 — Input validation note
 * Slider values read from the DOM are clamped via clampInt() before any logic
 * runs on them. This prevents crafted DOM manipulation from passing out-of-range
 * numbers into health score or array-index calculations.
 */

function riskMeta(v) {
  if (v <= 2) return { lbl: 'Very Conservative', col: '#10b981', bg: 'rgba(16,185,129,.15)' };
  if (v <= 4) return { lbl: 'Conservative',      col: '#06b6d4', bg: 'rgba(6,182,212,.15)'  };
  if (v <= 6) return { lbl: 'Moderate',          col: '#f59e0b', bg: 'rgba(245,158,11,.15)' };
  if (v <= 8) return { lbl: 'Aggressive',        col: '#f97316', bg: 'rgba(249,115,22,.15)' };
  return              { lbl: 'Very Aggressive',  col: '#ef4444', bg: 'rgba(239,68,68,.15)'  };
}

function updateAnalysis() {
  if (!portfolioData) return;
  const D = portfolioData;

  // clampInt() enforces the valid range regardless of what the DOM contains.
  const R  = clampInt(document.getElementById('riskSlider').value, 1, 10);
  const T  = clampInt(document.getElementById('timeSlider').value, 1, 5);
  const rm = riskMeta(R);
  const tl = TIMELABELS[T - 1];

  // textContent is always safe — no escaping needed for badge labels.
  const rb = document.getElementById('riskBadge');
  rb.textContent      = `${rm.lbl} (${R}/10)`;
  rb.style.background = rm.bg;
  rb.style.color      = rm.col;
  document.getElementById('timeBadge').textContent = tl;

  // Compute metrics
  const sorted      = [...D.holdings].sort((a, b) => b.marketValue - a.marketValue);
  const topH        = sorted[0];
  const topPct      = D.totalValue > 0 ? topH.marketValue / D.totalValue * 100 : 0;
  const techPct     = D.sectors['Technology'] ? D.sectors['Technology'].val / D.totalValue * 100 : 0;
  const cashPct     = D.cash / D.totalValue * 100;
  const sectorCount = Object.keys(D.sectors).filter(s => s !== 'Cash').length;
  const allPositive = D.holdings.every(h => h.gainLoss >= 0);
  const mixedDay    = D.holdings.some(h => h.dayChange < 0);

  // Health score
  let score = 50;
  score += allPositive ? 10 : 0;
  const concPenalty = topPct > 50 ? (R <= 3 ? 22 : R <= 5 ? 13 : R <= 7 ? 6 : 2)
                    : topPct > 35 ? (R <= 3 ? 12 : R <= 5 ?  6 : R <= 7 ? 2 : 0)
                    : 5;
  score -= concPenalty;
  if (sectorCount >= 4) score += 8;
  else if (sectorCount >= 3) score += 4;
  else score -= 6;
  if      (techPct > 70 && R <= 4) score -= 15;
  else if (techPct > 70 && R <= 6) score -= 6;
  if      (cashPct < 2  && R <= 4) score -= 8;
  else if (cashPct < 2  && R <= 6) score -= 3;
  if      (T >= 4) score += 12;
  else if (T >= 3) score += 5;
  else             score -= 3;
  if (D.totalGainLoss > 0) score += 8;
  score = Math.min(100, Math.max(8, score));

  let sc, sm;
  if      (score >= 72) { sc = '#10b981'; sm = 'Portfolio is well-aligned with your risk profile and goals'; }
  else if (score >= 50) { sc = '#f59e0b'; sm = 'Portfolio has areas that could be improved for your profile'; }
  else                  { sc = '#ef4444'; sm = 'Significant misalignment with your risk tolerance — action recommended'; }

  // textContent for all health panel output — safe without escaping.
  document.getElementById('healthNum').textContent        = score;
  document.getElementById('healthNum').style.color        = sc;
  document.getElementById('healthBar').style.width        = score + '%';
  document.getElementById('healthBar').style.background   = `linear-gradient(to right,${sc}55,${sc})`;
  document.getElementById('healthMeta').textContent       = sm;
  document.getElementById('healthCtx').textContent        = `${rm.lbl} risk · ${tl} horizon`;

  buildStrengths(R, T, D, topH, topPct, techPct, cashPct, sectorCount, allPositive, mixedDay);
  buildWeaknesses(R, T, D, topH, topPct, techPct, cashPct, sectorCount, allPositive);
  buildRecs(R, T, D, topH, topPct, techPct, cashPct, sectorCount);
}

// liG / liR build <li> HTML — the `txt` argument may contain esc()-wrapped symbols.
function liG(txt) { return `<li><span class="abul abul-g">✓</span><span>${txt}</span></li>`; }
function liR(txt) { return `<li><span class="abul abul-r">!</span><span>${txt}</span></li>`; }

function buildStrengths(R, T, D, topH, topPct, techPct, cashPct, sectorCount, allPositive, mixedDay) {
  const s = [];
  const sorted     = [...D.holdings].sort((a, b) => b.gainLossPct - a.gainLossPct);
  const bestGainer = sorted[0];

  // esc() wraps every OCR-derived ticker / name before it enters an HTML string.
  if (allPositive)
    s.push(`All ${D.holdings.length} positions are currently profitable — portfolio is ${D.totalGainLoss >= 0 ? 'up' : 'down'} ${esc(fmtPct(D.totalGainLossPct))} overall (+${esc(fmt(D.totalGainLoss))} total P&amp;L).`);
  else
    s.push(`Portfolio has a net gain of ${esc(fmt(D.totalGainLoss))} (${esc(fmtPct(D.totalGainLossPct))}), driven by ${esc(bestGainer.symbol)} (+${esc(fmtPct(bestGainer.gainLossPct))}).`);

  if (!mixedDay)
    s.push(`All positions are gaining today, with a combined daily increase of ${esc(fmt(D.totalDayChange))} (+${esc(fmtPct(D.totalDayPct))}).`);
  else if (D.totalDayChange > 0)
    s.push(`Net daily gain of ${esc(fmt(D.totalDayChange))} despite some positions moving down, showing overall portfolio resilience today.`);

  if (sectorCount >= 3) {
    // Sector names come from SECTOR_COLORS keys (whitelist), but escape anyway.
    const sectorList = Object.keys(D.sectors).filter(s => s !== 'Cash').map(esc).join(', ');
    s.push(`Portfolio spans ${sectorCount} sectors (${sectorList}), providing meaningful diversification across industries.`);
  }

  if (R >= 5 && techPct > 50)
    s.push(`Heavy tech weighting (${techPct.toFixed(1)}%) aligns with aggressive, high-growth strategy — well suited for investors seeking capital appreciation.`);

  const stable = D.holdings.filter(h => ['MSFT','AAPL','GOOGL','AMZN','BRK','JNJ','PG','KO'].includes(h.symbol));
  if (stable.length) {
    const stableList = stable.map(h => esc(h.symbol)).join(', ');
    s.push(`${stableList} provide${stable.length > 1 ? '' : 's'} blue-chip stability with proven track records and strong fundamentals.`);
  }

  if (T >= 4)
    s.push(`For a ${esc(TIMELABELS[T - 1])} horizon, growth-oriented holdings have ample time to compound and recover from short-term volatility.`);

  if (bestGainer.gainLossPct > 5)
    s.push(`${esc(bestGainer.symbol)} is your top performer at +${esc(fmtPct(bestGainer.gainLossPct))}, contributing ${esc(fmt(bestGainer.gainLoss))} to total portfolio gains.`);

  document.getElementById('strengthsList').innerHTML = s.slice(0, 5).map(liG).join('');
}

function buildWeaknesses(R, T, D, topH, topPct, techPct, cashPct, sectorCount, allPositive) {
  const w = [];
  const worstGainer = [...D.holdings].sort((a, b) => a.gainLossPct - b.gainLossPct)[0];

  if (topPct > 40) {
    const drop20 = (topH.marketValue * 0.20).toFixed(0);
    w.push(`${esc(topH.symbol)} is ${topPct.toFixed(1)}% of your portfolio — dangerous single-stock concentration. A 20% drop in ${esc(topH.symbol)} would erase ~$${Number(drop20).toLocaleString()}, ${R <= 5 ? 'nearly wiping out all your gains' : 'significantly impacting your portfolio'}.`);
  }

  if (techPct > 65 && R <= 6)
    w.push(`Technology makes up ${techPct.toFixed(1)}% of portfolio — heavy exposure to sector-wide risks: rate sensitivity, AI valuation cycles, regulatory pressure, and semiconductor cyclicality.`);

  if (cashPct < 3)
    w.push(`Only ${esc(fmt(D.cash))} (${cashPct.toFixed(1)}%) in cash — virtually no buying power. You cannot capitalize on market dips or new opportunities without liquidating existing positions.`);

  if (sectorCount < 3)
    w.push(`Portfolio spans only ${sectorCount} sector${sectorCount !== 1 ? 's' : ''}, leaving it highly vulnerable to sector-specific downturns without defensive alternatives.`);

  if (R <= 4)
    w.push(`No fixed-income or defensive positions (bonds, utilities, consumer staples). Conservative investors typically allocate 30–40% to lower-volatility assets as a buffer.`);

  if (T <= 2) {
    const cyclical = D.holdings.filter(h => ['FCX','CMC','X','AA','NUE','CLF'].includes(h.symbol));
    if (cyclical.length) {
      const cyclicalList = cyclical.map(h => esc(h.symbol)).join(', ');
      w.push(`${cyclicalList} ${cyclical.length > 1 ? 'are' : 'is'} cyclical and sensitive to macro conditions — near-term earnings/commodity risk is elevated for short-term holders.`);
    }
  }

  if (!allPositive || worstGainer.gainLossPct < 2)
    w.push(`${esc(worstGainer.symbol)} is your weakest position at ${esc(fmtPct(worstGainer.gainLossPct))} return — consider whether it fits your long-term thesis or should be rotated.`);

  w.push('100% domestic exposure with no international or emerging market allocation — missing global diversification and potentially undervalued non-US markets.');

  document.getElementById('weaknessesList').innerHTML = w.slice(0, 5).map(liR).join('');
}

/**
 * Builds a recommendation card. `title` and `body` are hardcoded strings
 * from this file only — they contain no OCR data. The `pri` arg is one of
 * 'high' | 'medium' | 'low', used only as a CSS class key lookup.
 */
function rec(pri, title, body) {
  const cls = { high: 'rh', medium: 'rm', low: 'rl' }[pri] || 'rl';
  return `<div class="rec"><span class="rpri ${cls}">${esc(pri)}</span><div class="rec-body"><strong>${title}</strong><p>${body}</p></div></div>`;
}

function buildRecs(R, T, D, topH, topPct, techPct, cashPct, sectorCount) {
  const recs = [];
  const tl   = TIMELABELS[T - 1];

  if (topPct > 40) {
    const trimTo = R <= 4 ? '20–25%' : R <= 6 ? '25–30%' : '30–35%';
    // topH.symbol used inside rec() body — safe because rec() does not call innerHTML directly;
    // the returned string is joined and set via innerHTML, so we escape here.
    recs.push(rec('high', `Reduce ${esc(topH.symbol)} Concentration`,
      `At ${topPct.toFixed(1)}% of portfolio, ${esc(topH.symbol)} carries outsized single-stock risk. Consider trimming to ~${trimTo} of total value and redeploying into broader ETFs (VOO, SPY) or other sectors to reduce concentration while staying invested.`));
  }

  if (R <= 5 && techPct > 60)
    recs.push(rec('high', 'Add Defensive Sector Exposure',
      `With ${techPct.toFixed(1)}% in technology, adding healthcare (XLV), consumer staples (XLP), or utilities (XLU) at 15–20% allocation would provide downside protection and lower overall portfolio volatility during tech selloffs.`));

  if (cashPct < 3)
    recs.push(rec('medium', 'Build Cash Reserve',
      `With only ${esc(fmt(D.cash))} available (${cashPct.toFixed(1)}%), you have no dry powder. Aim to keep ${R <= 5 ? '5–8%' : '3–5%'} in cash or a money market fund. Schwab's SWVXX currently yields ~4.8% APY — productive cash while waiting for opportunities.`));

  if (T >= 4)
    recs.push(rec('medium', 'Add Dividend Growth for Long-Term Compounding',
      `For a ${esc(tl)} horizon, dividend growth ETFs like SCHD or VIG quietly compound at 8–12% annually including reinvestments, balancing high-growth tech names with reliable income and lower volatility.`));

  if (T <= 2 && D.totalGainLoss > 100)
    recs.push(rec('high', 'Lock In Short-Term Profits',
      `With ${esc(fmt(D.totalGainLoss))} in unrealized gains and a ${esc(tl)} timeframe, consider taking partial profits (25–50%) on top gainers to crystallize returns and reduce exposure before any near-term pullback.`));

  if (R <= 4)
    recs.push(rec('medium', 'Introduce Fixed Income',
      `Conservative investors typically hold 30–40% in bonds or treasuries. Treasury ETFs like SGOV (T-bills, ~5.3% yield) or BND dramatically reduce portfolio volatility — the biggest alignment gap between your stated risk and current holdings.`));

  if (sectorCount < 4)
    recs.push(rec('medium', 'Diversify Across More Sectors',
      `Portfolio currently spans ${sectorCount} sector${sectorCount !== 1 ? 's' : ''}. Adding exposure to healthcare, financials, or industrials via sector ETFs would reduce correlation risk and smooth out returns across different economic cycles.`));

  if (T >= 3 && R >= 5)
    recs.push(rec('low', 'Consider International Diversification',
      `Adding 10–15% in VXUS or EEM captures emerging market growth (India, Southeast Asia) and reduces US policy/dollar concentration. International stocks are currently valued cheaply relative to US equities on most metrics.`));

  document.getElementById('recList').innerHTML = recs.slice(0, 5).join('');
}
