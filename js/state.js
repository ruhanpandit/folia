// ══════════════════════════════════════════════
//  GLOBAL STATE & CONSTANTS
// ══════════════════════════════════════════════
let portfolioData = null;
let selectedFile  = null;
let charts        = {};

const PALETTE = [
  '#3b82f6','#7c3aed','#10b981','#f59e0b','#ef4444',
  '#06b6d4','#f97316','#8b5cf6','#ec4899','#84cc16',
  '#a78bfa','#34d399','#fb7185','#38bdf8'
];

const SECTOR_COLORS = {
  'Technology':             '#3b82f6',
  'Communication Services': '#10b981',
  'Healthcare':             '#ec4899',
  'Financials':             '#f59e0b',
  'Consumer Discretionary': '#8b5cf6',
  'Consumer Staples':       '#06b6d4',
  'Energy':                 '#f97316',
  'Materials':              '#84cc16',
  'Industrials':            '#64748b',
  'Real Estate':            '#a78bfa',
  'Utilities':              '#fbbf24',
  'Cash':                   '#475569'
};

const TIMELABELS = ['< 3 months','3–6 months','6–12 months','1–2 years','3+ years'];

// ── Shared helpers ──────────────────────────
const delay = ms => new Promise(r => setTimeout(r, ms));

function fmt(n, prefix='$') {
  if (n === undefined || n === null) return '—';
  const s = Math.abs(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return (n < 0 ? '-' : '') + prefix + s;
}

function fmtPct(n) {
  if (!n && n !== 0) return '—';
  return (n >= 0 ? '+' : '') + n.toFixed(2) + '%';
}

// ── Security helpers ─────────────────────────────────────────────────────────

/**
 * OWASP A03 — XSS Prevention
 * Escapes HTML special characters before injecting any string into innerHTML.
 * Must be applied to ALL OCR-derived text (ticker symbols, company names,
 * sector names) since that content originates from an untrusted image file.
 */
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * OWASP A03 — Input Validation
 * Clamps a DOM-sourced numeric value to a known-safe integer range.
 * Prevents crafted DOM manipulation from passing out-of-range values into
 * the health-score and analysis logic.
 *
 * @param {*}      val  Raw value from an input element
 * @param {number} min  Inclusive lower bound
 * @param {number} max  Inclusive upper bound
 * @returns {number}    Integer clamped within [min, max]
 */
function clampInt(val, min, max) {
  const n = parseInt(val, 10);
  if (isNaN(n)) return min;
  return Math.min(max, Math.max(min, n));
}
