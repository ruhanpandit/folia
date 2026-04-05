// ══════════════════════════════════════════════
//  SECURITY — FILE VALIDATION (OWASP A03)
// ══════════════════════════════════════════════

/**
 * Allowed image MIME types. The HTML accept="image/*" attribute is a UI hint
 * only — any file can be dropped or programmatically submitted, so we re-check
 * here in JS before handing the file to the OCR engine.
 */
const ALLOWED_MIME_TYPES = new Set([
  'image/png', 'image/jpeg', 'image/webp',
  'image/gif', 'image/bmp', 'image/tiff',
]);

const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024; // 25 MB — generous for full-res screenshots
const MAX_FILENAME_LENGTH = 255;

/**
 * Validates a File object before it is processed by OCR.
 * Throws a user-facing Error if validation fails.
 *
 * Checks (OWASP A03 — input validation):
 *  1. MIME type must be in the allowed image set
 *  2. File size must not exceed 25 MB
 *  3. Filename length must not exceed 255 characters
 */
function validateFile(file) {
  if (!file || !(file instanceof File)) {
    throw new Error('Invalid file object. Please try selecting your image again.');
  }
  if (!ALLOWED_MIME_TYPES.has(file.type)) {
    throw new Error(
      `Unsupported file type "${esc(file.type) || 'unknown'}". ` +
      'Please upload a PNG, JPG, or WebP screenshot of your portfolio.'
    );
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
    const mb = (file.size / 1_048_576).toFixed(1);
    throw new Error(
      `File is too large (${mb} MB). Maximum allowed size is 25 MB. ` +
      'Try taking a screenshot of just the holdings table.'
    );
  }
  if (file.name && file.name.length > MAX_FILENAME_LENGTH) {
    throw new Error('Filename is too long. Please rename the file and try again.');
  }
}

// ══════════════════════════════════════════════
//  SECURITY — CLIENT-SIDE RATE LIMITING (OWASP A04)
// ══════════════════════════════════════════════

/**
 * NOTE — this app is entirely client-side with no server endpoints.
 * Traditional IP/user-based server rate limiting is not applicable here.
 * Instead we enforce limits inside the browser to:
 *   - Prevent the OCR engine from being invoked in rapid succession
 *     (each run downloads ~10 MB of language data and saturates the CPU)
 *   - Give the user a clear feedback loop if they mash the button
 *
 * These limits are intentionally lenient (suitable for a portfolio tool),
 * but the pattern can be tightened by adjusting the constants below.
 */
const RATE_LIMIT = {
  MIN_INTERVAL_MS: 8_000,  // minimum 8 s between analyses
  MAX_PER_SESSION: 30,      // max 30 analyses per browser session
  _count: 0,
  _lastMs: 0,
  _busy: false,             // true while an analysis is in flight
};

/**
 * Throws if the current request exceeds rate-limit thresholds.
 * Must be called synchronously before any async work begins so the
 * button can be re-enabled immediately on rejection.
 */
function enforceRateLimit() {
  if (RATE_LIMIT._busy) {
    throw new Error('An analysis is already running. Please wait for it to finish.');
  }
  if (RATE_LIMIT._count >= RATE_LIMIT.MAX_PER_SESSION) {
    throw new Error(
      'You have reached the maximum number of analyses for this session. ' +
      'Refresh the page to continue.'
    );
  }
  const elapsed = Date.now() - RATE_LIMIT._lastMs;
  if (RATE_LIMIT._lastMs > 0 && elapsed < RATE_LIMIT.MIN_INTERVAL_MS) {
    const wait = Math.ceil((RATE_LIMIT.MIN_INTERVAL_MS - elapsed) / 1000);
    throw new Error(
      `Please wait ${wait} more second${wait !== 1 ? 's' : ''} before analyzing again.`
    );
  }
}

// ══════════════════════════════════════════════
//  UPLOAD FLOW
// ══════════════════════════════════════════════
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');

window.addEventListener('DOMContentLoaded', () => checkReady());

fileInput.addEventListener('change', e => {
  if (e.target.files[0]) setFile(e.target.files[0]);
});
dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', e => {
  e.preventDefault(); dropzone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});

/**
 * Stores the selected file after passing validation.
 * Validation runs here (on select) so the user gets immediate feedback
 * rather than waiting until they click Analyze.
 */
function setFile(file) {
  clearError();
  try {
    validateFile(file);
  } catch (err) {
    showError(err.message);
    selectedFile = null;
    checkReady();
    return;
  }

  selectedFile = file;
  // Use textContent (not innerHTML) for the filename — no XSS risk from filenames
  document.getElementById('dzPreviewImg').src = URL.createObjectURL(file);
  document.getElementById('dzFileName').textContent = file.name;
  document.getElementById('dzDefault').style.display = 'none';
  document.getElementById('dzPreview').style.display  = 'flex';
  checkReady();
}

function checkReady() {
  document.getElementById('analyzeBtn').disabled = !selectedFile;
}

// textContent used intentionally — avoids XSS from error message strings
function showError(msg) {
  const box = document.getElementById('errorBox');
  box.textContent = msg;
  box.style.display = 'block';
}
function clearError() { document.getElementById('errorBox').style.display = 'none'; }

// ══════════════════════════════════════════════
//  ANALYSIS TRIGGER
// ══════════════════════════════════════════════
async function startAnalysis() {
  if (!selectedFile) return;
  clearError();

  // ── Validate & rate-limit before touching the UI ──────────────────────────
  // Both checks are synchronous so we can bail out without side-effects.
  try {
    validateFile(selectedFile);   // re-validate in case file object changed
    enforceRateLimit();
  } catch (err) {
    showError(err.message);
    return;
  }

  // ── Lock UI to prevent double-submission ─────────────────────────────────
  RATE_LIMIT._busy = true;
  document.getElementById('analyzeBtn').disabled = true;
  document.getElementById('uploadScreen').style.display  = 'none';
  document.getElementById('loadingScreen').style.display = 'flex';

  try {
    const raw = await extractWithOCR(selectedFile);
    stepDone(2); stepActive(3);

    const data = parsePortfolioText(raw);
    if (!data || !data.holdings || data.holdings.length === 0)
      throw new Error(
        'No holdings found. Make sure the screenshot clearly shows your ' +
        'positions table with tickers and dollar values.'
      );

    portfolioData = enrichData(data);

    // Record successful analysis for rate limiting
    RATE_LIMIT._count++;
    RATE_LIMIT._lastMs = Date.now();

    await delay(300);
    stepDone(3);
    await delay(200);
    showApp();
  } catch (err) {
    document.getElementById('loadingScreen').style.display = 'none';
    document.getElementById('uploadScreen').style.display  = 'flex';
    showError(err.message || 'Something went wrong. Please try again with a clearer screenshot.');
  } finally {
    // Always unlock — whether analysis succeeded or failed
    RATE_LIMIT._busy = false;
    document.getElementById('analyzeBtn').disabled = !selectedFile;
  }
}

function stepActive(n) { document.getElementById('step' + n)?.classList.add('active'); }
function stepDone(n) {
  const el = document.getElementById('step' + n);
  el?.classList.remove('active');
  el?.classList.add('done');
}
function resetSteps() {
  for (let i = 1; i <= 3; i++) {
    const el = document.getElementById('step' + i);
    el.classList.remove('active', 'done');
  }
  document.getElementById('step1').classList.add('active');
}

// ══════════════════════════════════════════════
//  TESSERACT OCR
// ══════════════════════════════════════════════
async function extractWithOCR(file) {
  const progressEl = document.getElementById('ocrProgress');

  const worker = await Tesseract.createWorker('eng', 1, {
    logger: m => {
      if (m.status === 'loading tesseract core') {
        progressEl.textContent = 'Loading OCR engine…';
      } else if (m.status === 'loading language traineddata') {
        progressEl.textContent = `Loading language data… ${Math.round(m.progress * 100)}%`;
      } else if (m.status === 'initializing api') {
        progressEl.textContent = 'Initializing…';
        stepDone(1); stepActive(2);
      } else if (m.status === 'recognizing text') {
        progressEl.textContent = `Reading image… ${Math.round(m.progress * 100)}%`;
      }
    }
  });

  // PSM 6 = single uniform block — reads tables more predictably than auto mode
  await worker.setParameters({ tessedit_pagesegmode: '6' });

  const imageUrl = URL.createObjectURL(file);
  const { data: { text } } = await worker.recognize(imageUrl);
  await worker.terminate();
  URL.revokeObjectURL(imageUrl);
  // Log raw OCR output to the browser console for debugging
  console.log('=== RAW OCR TEXT ===\n' + text);
  return text;
}

// ══════════════════════════════════════════════
//  TEXT PARSER
// ══════════════════════════════════════════════
function parsePortfolioText(rawText) {

  const parseDollar = raw => {
    if (!raw) return null;
    const s = raw.replace(/\s/g, '');
    const neg = s.startsWith('-') || s.includes('(-') || /\([\d]/.test(s);
    const n = parseFloat(s.replace(/[^0-9.]/g, ''));
    return isNaN(n) ? null : (neg ? -n : n);
  };

  const SKIP = new Set([
    // Brokerage column headers / section labels
    'AND','THE','FOR','INC','CO','CORP','LLC','LTD','ETF','ADR','USD',
    'QTY','MKT','VAL','PRC','CHG','DAY','NET','TOT','SYM','APY','DIV',
    'SYMBOL','NAME','QUANTITY','PRICE','MARKET','VALUE','CHANGE','GAIN',
    'LOSS','TOTAL','CASH','EQUITIES','MONEY','TYPE','AMOUNT','ALL',
    'BUY','SEL','NUM','PRE','POS','PNL','YTD','AUM','NAV','YLD',
    // Schwab-specific UI text fragments
    'ACCT','FUND','INDV','INDI','AVBL','AVAI','BALS','PERF','ALLOC',
    'INVS','INVT','INVE','MKTV','COST','FEES','COMM','ACNT','SECT',
    'HOLD','PORT','SUMM','OVER','DETL','ACTI','HIST','ORDE','POSI',
    // Common English words that are never stock tickers
    'IS','AS','AT','BY','DO','GO','IF','IN','IT','MY','NO','OF',
    'OR','UP','US','WE','AN','AM','BE','HE','ME','HI','OH','OK',
    'ARE','BUT','CAN','DID','GET','GOT','HAD','HAS','HER','HIM',
    'HOW','HIS','ITS','LET','MAY','NEW','NOT','NOW','OLD','OUR',
    'OUT','OWN','PUT','SAY','SEE','SHE','TOO','USE','WAY','WHO',
    'WHY','WAS','YES','YET','YOU','ALSO','BACK','BEEN','BOTH','CAME',
    'COME','DOES','DOWN','EACH','ELSE','EVEN','EVER','FROM','GIVE',
    'GOES','GONE','GOOD','HAVE','HERE','HIGH','HOME','INTO','JUST',
    'KEEP','KIND','KNOW','LAST','LEFT','LIKE','LONG','LOOK','MADE',
    'MAKE','MANY','MEAN','MUCH','MUST','NEXT','ONLY','OPEN','PART',
    'PAST','RATE','READ','REAL','RISK','SAME','SHOW','SIDE','SIZE',
    'SOME','SOON','SUCH','SURE','TAKE','TELL','THAN','THEM','THEN',
    'THEY','THIS','THAT','THUS','TIME','UPON','USED','VIEW','WANT',
    'WELL','WENT','WERE','WILL','WITH','WORD','WORK','YEAR','YOUR',
    'PLAN','LESS','MORE','MOST','BEST','NEXT','LAST','FIRST','ONLY',
  ]);

  // Strip non-ASCII (removes ‡ and other Schwab decorators) then split lines
  const lines = rawText
    .split('\n')
    .map(l => l.replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim())
    .filter(l => l.length > 0);

  const tickerRe = /^([A-Z]{2,5})(\s|$)/;
  // Matches a company suffix immediately at the start of the remaining text,
  // e.g. rest="CORP" or rest="CORP 0.1396 $1,516.84..." both start with CORP.
  // This catches "KLA CORP" whether or not stock data follows on the same line.
  const DIRECT_SUFFIX = /^(CORP|INC|LTD|LLC|PLC|GROUP|HOLDINGS|TRUST|REIT)\b/;
  // Catches pure company-name-only lines like "KLA CORP" (no digits at all)
  const CO_SUFFIX_ONLY = /\b(CORP|INC|LTD|LLC|PLC|GROUP|HOLDINGS|TRUST|REIT|DEVIC)\b/;

  // ── PASS 1: locate all ticker line indices ──
  const rawPositions = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(tickerRe);
    if (!m || SKIP.has(m[1])) continue;

    const rest = lines[i].slice(m[1].length).trim();

    // Case A: "KLA CORP" — rest has no digits and contains a company suffix
    if (rest.length > 0 && !/\d/.test(rest) && /^[A-Z\s&.,'\-]+$/.test(rest) && CO_SUFFIX_ONLY.test(rest)) continue;

    // Case B: "KLA CORP 0.1396 $1,516.84..." — rest starts DIRECTLY with a suffix word
    // (the token before the first digit is a company suffix, meaning the 2-5 char prefix
    //  is NOT the real ticker — the real ticker already appeared on the line above)
    if (rest.length > 0 && DIRECT_SUFFIX.test(rest)) continue;

    rawPositions.push({ idx: i, sym: m[1] });
  }

  // Post-process: if a shorter symbol immediately follows a longer one that starts
  // with it (e.g. "KLA" 1-2 lines after "KLAC"), it's a company-name fragment — drop it.
  const tickerPositions = rawPositions.filter((cur, t) => {
    if (t === 0) return true;
    const prev = rawPositions[t - 1];
    return !(prev.sym.startsWith(cur.sym) && cur.idx - prev.idx <= 2);
  });

  if (tickerPositions.length === 0)
    return { holdings: [], cash: 0, totalEquitiesValue: 0, totalDayChange: 0, totalGainLoss: 0 };

  // ── PASS 2: parse each holding block ──
  const DOLLAR_RE = /[+\-]?\$[\d,]+\.?\d*/g;
  const holdings = [];

  for (let t = 0; t < tickerPositions.length; t++) {
    const { idx, sym } = tickerPositions[t];

    const nextIdx = t + 1 < tickerPositions.length ? tickerPositions[t + 1].idx : lines.length;
    const blockEnd = Math.min(nextIdx, idx + 10);
    const block = lines.slice(idx, blockEnd);
    const combined = block.join(' ');

    // ── company name ──
    let name = sym;
    const afterTicker = block[0].slice(sym.length).trim();
    if (afterTicker && /^[A-Z][A-Z\s&.,']+$/.test(afterTicker)) {
      name = afterTicker;
    } else {
      for (const bl of block.slice(1, 4)) {
        if (bl.length > 2 && /^[A-Z][A-Z\s&.,']{1,}$/.test(bl) && !/\d/.test(bl)) {
          name = bl;
          break;
        }
      }
    }

    // ── dollar amounts ──
    const dollarMatches = combined.match(DOLLAR_RE) || [];
    const dollars = dollarMatches.map(parseDollar).filter(d => d !== null);

    if (dollars.length < 2) continue;

    // ── column mapping ──
    let price = 0, priceChange = 0, marketValue = 0, dayChange = 0, gainLoss = 0;

    if (dollars.length >= 5) {
      // Full Schwab row: Price | PriceChange | MarketValue | DayChange | GainLoss
      // Trust positional order — do NOT swap. KLAC has price $1,516 > MV $211 (fractional share).
      price       = Math.abs(dollars[0]);
      priceChange = dollars[1];
      marketValue = Math.abs(dollars[2]);
      dayChange   = dollars[3];
      gainLoss    = dollars[4];
    } else if (dollars.length === 4) {
      price       = Math.abs(dollars[0]);
      marketValue = Math.abs(dollars[1]);
      dayChange   = dollars[2];
      gainLoss    = dollars[3];
      // Heuristic swap only for ambiguous partial rows
      if (price > marketValue && price > 0) [price, marketValue] = [marketValue, price];
    } else if (dollars.length === 3) {
      price       = Math.abs(dollars[0]);
      marketValue = Math.abs(dollars[1]);
      gainLoss    = dollars[2];
      if (price > marketValue && price > 0) [price, marketValue] = [marketValue, price];
    } else {
      price       = Math.abs(dollars[0]);
      marketValue = Math.abs(dollars[1]);
      if (price > marketValue && price > 0) [price, marketValue] = [marketValue, price];
    }

    // ── quantity ──
    const noDollars = combined.replace(DOLLAR_RE, '');
    const fracMatch  = noDollars.match(/\b(\d+\.\d{2,})\b/);
    const wholeMatch = noDollars.match(/\b([1-9]\d{0,4})\b/);
    const quantity   = fracMatch ? parseFloat(fracMatch[1]) : wholeMatch ? parseInt(wholeMatch[1]) : 0;

    // Require a meaningful market value — filters out UI text false positives
    if (marketValue > 0.50) {
      holdings.push({ symbol: sym, name, quantity, price, priceChange,
                      marketValue, dayChange, gainLoss, sector: inferSector(sym) });
    }
  }

  // ── cash ──
  let cash = 0;
  const fullText = lines.join(' ');
  const cashInvestRe = /cash[^$]{0,60}invest[^$]{0,40}\$([\d,]+\.?\d*)/i;
  const cashTotalRe  = /money\s*market[^$]{0,40}total[^$]{0,40}\$([\d,]+\.?\d*)/i;
  const cm = fullText.match(cashInvestRe) || fullText.match(cashTotalRe);
  if (cm) cash = parseFloat(cm[1].replace(/,/g, '')) || 0;

  // ── totals ──
  let totalEquitiesValue = 0, totalDayChange = 0, totalGainLoss = 0;
  const totLine = lines.find(l => /equities\s*total/i.test(l));
  if (totLine) {
    const td = (totLine.match(DOLLAR_RE) || []).map(parseDollar).filter(Boolean);
    if (td[0]) totalEquitiesValue = Math.abs(td[0]);
    if (td[1]) totalDayChange = td[1];
    if (td[2]) totalGainLoss = td[2];
  }

  return { holdings, cash, totalEquitiesValue, totalDayChange, totalGainLoss };
}

// ══════════════════════════════════════════════
//  SECTOR LOOKUP
// ══════════════════════════════════════════════
function inferSector(sym) {
  const map = {
    // Technology
    AMD:'Technology',NVDA:'Technology',INTC:'Technology',MSFT:'Technology',AAPL:'Technology',
    GOOGL:'Technology',GOOG:'Technology',META:'Technology',AMZN:'Technology',CRM:'Technology',
    ORCL:'Technology',IBM:'Technology',CSCO:'Technology',QCOM:'Technology',AVGO:'Technology',
    TXN:'Technology',KLAC:'Technology',AMAT:'Technology',LRCX:'Technology',MU:'Technology',
    MRVL:'Technology',NXPI:'Technology',ON:'Technology',DELL:'Technology',HPQ:'Technology',
    HPE:'Technology',ADBE:'Technology',NOW:'Technology',SNOW:'Technology',PLTR:'Technology',
    UBER:'Technology',SPOT:'Technology',DDOG:'Technology',NET:'Technology',CRWD:'Technology',
    PANW:'Technology',ZS:'Technology',OKTA:'Technology',SHOP:'Technology',SQ:'Technology',
    PYPL:'Technology',COIN:'Technology',HOOD:'Technology',SOFI:'Technology',SMCI:'Technology',
    ARM:'Technology',AFRM:'Technology',LYFT:'Technology',TWLO:'Technology',ZM:'Technology',
    // Communication Services
    NFLX:'Communication Services',DIS:'Communication Services',CMCSA:'Communication Services',
    T:'Communication Services',VZ:'Communication Services',TMUS:'Communication Services',
    CHTR:'Communication Services',WBD:'Communication Services',PARA:'Communication Services',
    FOX:'Communication Services',EA:'Communication Services',TTWO:'Communication Services',
    RBLX:'Communication Services',SNAP:'Communication Services',PINS:'Communication Services',
    RDDT:'Communication Services',
    // Materials
    FCX:'Materials',CMC:'Materials',NUE:'Materials',STLD:'Materials',CLF:'Materials',
    AA:'Materials',ALB:'Materials',NEM:'Materials',GOLD:'Materials',VALE:'Materials',
    RIO:'Materials',BHP:'Materials',DOW:'Materials',LYB:'Materials',PPG:'Materials',SHW:'Materials',
    // Healthcare
    JNJ:'Healthcare',PFE:'Healthcare',MRK:'Healthcare',ABBV:'Healthcare',LLY:'Healthcare',
    BMY:'Healthcare',AMGN:'Healthcare',GILD:'Healthcare',CVS:'Healthcare',UNH:'Healthcare',
    HUM:'Healthcare',CI:'Healthcare',ELV:'Healthcare',MDT:'Healthcare',ABT:'Healthcare',
    TMO:'Healthcare',DHR:'Healthcare',BSX:'Healthcare',SYK:'Healthcare',ISRG:'Healthcare',
    REGN:'Healthcare',VRTX:'Healthcare',BIIB:'Healthcare',ILMN:'Healthcare',
    // Financials
    JPM:'Financials',BAC:'Financials',WFC:'Financials',GS:'Financials',MS:'Financials',
    C:'Financials',BLK:'Financials',V:'Financials',MA:'Financials',AXP:'Financials',
    SCHW:'Financials',COF:'Financials',DFS:'Financials',USB:'Financials',PNC:'Financials',TFC:'Financials',
    // Consumer Discretionary
    TSLA:'Consumer Discretionary',HD:'Consumer Discretionary',MCD:'Consumer Discretionary',
    NKE:'Consumer Discretionary',SBUX:'Consumer Discretionary',TGT:'Consumer Discretionary',
    LOW:'Consumer Discretionary',F:'Consumer Discretionary',GM:'Consumer Discretionary',
    BKNG:'Consumer Discretionary',ABNB:'Consumer Discretionary',EXPE:'Consumer Discretionary',
    // Consumer Staples
    PG:'Consumer Staples',KO:'Consumer Staples',PEP:'Consumer Staples',WMT:'Consumer Staples',
    COST:'Consumer Staples',PM:'Consumer Staples',MO:'Consumer Staples',CL:'Consumer Staples',
    KHC:'Consumer Staples',GIS:'Consumer Staples',
    // Energy
    XOM:'Energy',CVX:'Energy',COP:'Energy',SLB:'Energy',MPC:'Energy',VLO:'Energy',
    PSX:'Energy',OXY:'Energy',EOG:'Energy',PXD:'Energy',DVN:'Energy',HAL:'Energy',
    // Industrials
    CAT:'Industrials',DE:'Industrials',BA:'Industrials',GE:'Industrials',HON:'Industrials',
    MMM:'Industrials',RTX:'Industrials',LMT:'Industrials',UPS:'Industrials',FDX:'Industrials',
    WM:'Industrials',RSG:'Industrials',NOC:'Industrials',GD:'Industrials',
    // Utilities
    NEE:'Utilities',DUK:'Utilities',SO:'Utilities',D:'Utilities',AEP:'Utilities',
    EXC:'Utilities',SRE:'Utilities',PCG:'Utilities',
    // Real Estate
    AMT:'Real Estate',PLD:'Real Estate',EQIX:'Real Estate',SPG:'Real Estate',
    O:'Real Estate',WPC:'Real Estate',VICI:'Real Estate',AVB:'Real Estate',
  };
  return map[sym] || 'Technology';
}

// ══════════════════════════════════════════════
//  DATA ENRICHMENT
// ══════════════════════════════════════════════
function enrichData(raw) {
  const holdings = raw.holdings.map((h, i) => ({
    ...h,
    color: PALETTE[i % PALETTE.length],
    costBasis: h.marketValue - h.gainLoss,
    gainLossPct: h.marketValue > 0 ? (h.gainLoss / (h.marketValue - h.gainLoss)) * 100 : 0
  }));

  const equitiesValue = raw.totalEquitiesValue || holdings.reduce((s, h) => s + h.marketValue, 0);
  const cash          = raw.cash || 0;
  const totalValue    = equitiesValue + cash;
  const totalDayChange  = raw.totalDayChange  || holdings.reduce((s, h) => s + h.dayChange, 0);
  const totalGainLoss   = raw.totalGainLoss   || holdings.reduce((s, h) => s + h.gainLoss,  0);
  const totalCostBasis  = holdings.reduce((s, h) => s + h.costBasis, 0);
  const totalGainLossPct = totalCostBasis > 0 ? (totalGainLoss / totalCostBasis) * 100 : 0;
  const totalDayPct      = (totalValue - totalDayChange) > 0 ? (totalDayChange / (totalValue - totalDayChange)) * 100 : 0;

  const sectors = {};
  holdings.forEach(h => {
    const s = h.sector || 'Other';
    if (!sectors[s]) sectors[s] = { val: 0, col: SECTOR_COLORS[s] || '#475569' };
    sectors[s].val += h.marketValue;
  });
  if (cash > 0) sectors['Cash'] = { val: cash, col: SECTOR_COLORS['Cash'] };

  return { holdings, cash, equitiesValue, totalValue, totalDayChange, totalDayPct,
           totalGainLoss, totalGainLossPct, sectors };
}

// ══════════════════════════════════════════════
//  SHOW / HIDE APP
// ══════════════════════════════════════════════
function showApp() {
  document.getElementById('loadingScreen').style.display = 'none';
  const app = document.getElementById('appContainer');
  app.style.display = 'block';

  if (selectedFile) {
    const th = document.getElementById('headerThumb');
    th.src = URL.createObjectURL(selectedFile);
    th.style.display = 'block';
  }

  renderDashboard();
  updateAnalysis();
}

function showUpload() {
  Object.values(charts).forEach(c => c && c.destroy && c.destroy());
  charts = {};
  document.getElementById('appContainer').style.display = 'none';
  document.getElementById('uploadScreen').style.display = 'flex';
  clearError();
  resetSteps();
  document.querySelectorAll('.ctab').forEach((t, i) => t.classList.toggle('active', i === 0));
  document.querySelectorAll('.cpanel,.cpanel-bar').forEach(p => p.classList.remove('active'));
  document.getElementById('cpanel-alloc').classList.add('active');
}
