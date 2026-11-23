(() => {
  'use strict';

  const STORAGE_KEY_LOCAL = 'pa_vault_pass_v1';
  const STORAGE_KEY_SESSION = 'pa_vault_pass_session_v1';
  const VAULT_MAGIC = 'PA01';
  const HEADER_LEN = 36; // 4 magic + 4 iterations + 16 salt + 12 iv

  const MONTHS_GEN = [
    'января', 'февраля', 'марта', 'апреля', 'мая', 'июня',
    'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'
  ];
  const MONTHS_SHORT = [
    'янв', 'фев', 'мар', 'апр', 'май', 'июн',
    'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'
  ];

  // State
  let appData = null;
  let objectUrls = [];
  let activeTab = 'path';
  let showFutureWeeks = false;
  let lightboxPhotos = [];
  let lightboxIndex = 0;
  let touchStartX = null;

  // DOM refs
  const lockScreen = document.getElementById('lock-screen');
  const lockCard = lockScreen.querySelector('.lock-card');
  const unlockForm = document.getElementById('unlock-form');
  const passwordInput = document.getElementById('password-input');
  const togglePassBtn = document.getElementById('toggle-pass-btn');
  const rememberCheckbox = document.getElementById('remember-checkbox');
  const unlockBtn = document.getElementById('unlock-btn');
  const lockError = document.getElementById('lock-error');

  const appShell = document.getElementById('app-shell');
  const appTitleEl = document.getElementById('app-title');
  const lockBtn = document.getElementById('lock-btn');

  const tabPath = document.getElementById('tab-path');
  const tabMemories = document.getElementById('tab-memories');
  const pathContent = document.getElementById('path-content');
  const memoriesContent = document.getElementById('memories-content');
  const memoriesCountBadge = document.getElementById('memories-count-badge');
  const navBtns = Array.from(document.querySelectorAll('.nav-btn'));

  const lightbox = document.getElementById('lightbox');
  const lightboxBackdrop = document.getElementById('lightbox-backdrop');
  const lightboxClose = document.getElementById('lightbox-close');
  const lightboxStage = document.getElementById('lightbox-stage');
  const lightboxImg = document.getElementById('lightbox-img');
  const lightboxPrev = document.getElementById('lightbox-prev');
  const lightboxNext = document.getElementById('lightbox-next');
  const lightboxCounter = document.getElementById('lightbox-counter');
  const lightboxCaption = document.getElementById('lightbox-caption');
  const lightboxMeta = document.getElementById('lightbox-meta');

  /* ---------- Utilities ---------- */

  function escHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function parseIsoDate(iso) {
    const [y, m, d] = iso.split('-').map(Number);
    return new Date(y, m - 1, d);
  }

  function toIsoDate(date) {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }

  function addDays(date, days) {
    const d = new Date(date.getFullYear(), date.getMonth(), date.getDate());
    d.setDate(d.getDate() + days);
    return d;
  }

  function diffDays(fromDate, toDate) {
    const a = Date.UTC(fromDate.getFullYear(), fromDate.getMonth(), fromDate.getDate());
    const b = Date.UTC(toDate.getFullYear(), toDate.getMonth(), toDate.getDate());
    return Math.round((b - a) / 86400000);
  }

  function formatDateRu(iso) {
    const d = parseIsoDate(iso);
    return `${d.getDate()} ${MONTHS_GEN[d.getMonth()]} ${d.getFullYear()}`;
  }

  function formatDateDot(iso) {
    const d = parseIsoDate(iso);
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    return `${dd}.${mm}.${d.getFullYear()}`;
  }

  function formatWeekRange(startDate, endDate) {
    const d1 = startDate.getDate();
    const m1 = MONTHS_SHORT[startDate.getMonth()];
    const d2 = endDate.getDate();
    const m2 = MONTHS_SHORT[endDate.getMonth()];
    if (m1 === m2) {
      return `${d1}–${d2} ${m2}`;
    }
    return `${d1} ${m1} – ${d2} ${m2}`;
  }

  function pluralRu(n, one, few, many) {
    const abs = Math.abs(n) % 100;
    const mod10 = abs % 10;
    if (abs > 10 && abs < 20) return many;
    if (mod10 > 1 && mod10 < 5) return few;
    if (mod10 === 1) return one;
    return many;
  }

  function revokeObjectUrls() {
    for (const url of objectUrls) {
      URL.revokeObjectURL(url);
    }
    objectUrls = [];
  }

  /* ---------- Web Crypto Local Decryption ---------- */

  async function decryptVaultBuffer(arrayBuffer, password) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('NO_SUBTLE_CRYPTO');
    }
    const bytes = new Uint8Array(arrayBuffer);
    if (bytes.length < HEADER_LEN + 16) {
      throw new Error('CORRUPT_VAULT');
    }

    const magic = new TextDecoder().decode(bytes.subarray(0, 4));
    if (magic !== VAULT_MAGIC) {
      throw new Error('BAD_MAGIC');
    }

    const view = new DataView(arrayBuffer);
    const iterations = view.getUint32(4, false);
    const salt = bytes.subarray(8, 24);
    const iv = bytes.subarray(24, 36);
    const aad = bytes.subarray(0, HEADER_LEN);
    const ciphertext = bytes.subarray(HEADER_LEN);

    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const plainBuf = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad,
        tagLength: 128,
      },
      aesKey,
      ciphertext
    );

    // Unpack binary bundle: [4-byte uint32 BE json_len][json_utf8][photo_blobs...]
    const plainView = new DataView(plainBuf);
    const jsonLen = plainView.getUint32(0, false);
    const plainBytes = new Uint8Array(plainBuf);
    const jsonText = new TextDecoder().decode(plainBytes.subarray(4, 4 + jsonLen));
    const parsed = JSON.parse(jsonText);

    const blobsBase = 4 + jsonLen;
    revokeObjectUrls();

    for (const mem of parsed.memories || []) {
      for (const photo of mem.photos || []) {
        const start = blobsBase + photo.offset;
        const end = start + photo.length;
        const slice = plainBytes.subarray(start, end);
        const blob = new Blob([slice], { type: photo.mime || 'image/jpeg' });
        const url = URL.createObjectURL(blob);
        objectUrls.push(url);
        photo.url = url;
      }
    }

    return parsed;
  }

  async function fetchAndUnlock(password, { silent = false } = {}) {
    if (!silent) {
      lockError.hidden = true;
      unlockBtn.disabled = true;
      unlockBtn.querySelector('.btn-label').textContent = 'Расшифровываем…';
    }

    try {
      const res = await fetch('./vault.enc', { cache: 'no-store' });
      if (!res.ok) {
        throw new Error('FETCH_FAILED');
      }
      const buf = await res.arrayBuffer();
      const data = await decryptVaultBuffer(buf, password);

      appData = data;
      try {
        sessionStorage.setItem(STORAGE_KEY_SESSION, password);
        if (rememberCheckbox.checked) {
          localStorage.setItem(STORAGE_KEY_LOCAL, password);
        } else {
          localStorage.removeItem(STORAGE_KEY_LOCAL);
        }
      } catch (_) {
        // Ignore storage quota / private mode restrictions
      }

      renderAll();
      lockScreen.hidden = true;
      appShell.hidden = false;
      passwordInput.value = '';
    } catch (err) {
      if (!silent) {
        let msg = 'Не тот пароль — попробуй ещё разок!';
        if (err && err.message === 'NO_SUBTLE_CRYPTO') {
          msg = 'Для расшифровки нужен HTTPS или localhost (браузер отключил Web Crypto на незащищённом HTTP).';
        } else if (err && err.message === 'FETCH_FAILED') {
          msg = 'Не удалось загрузить vault.enc. Проверь интернет или пересобери сайт.';
        } else if (err && (err.message === 'CORRUPT_VAULT' || err.message === 'BAD_MAGIC')) {
          msg = 'Файл vault.enc повреждён — нужно пересобрать его командой ./build.sh.';
        }
        lockError.textContent = msg;
        lockError.hidden = false;
        lockCard.classList.remove('is-shaking');
        void lockCard.offsetWidth;
        lockCard.classList.add('is-shaking');
      } else {
        // Stored password changed -> clear saved password silently
        try {
          localStorage.removeItem(STORAGE_KEY_LOCAL);
          sessionStorage.removeItem(STORAGE_KEY_SESSION);
        } catch (_) {}
      }
    } finally {
      if (!silent) {
        unlockBtn.disabled = false;
        unlockBtn.querySelector('.btn-label').textContent = 'Открыть!';
      }
    }
  }

  function lockApp() {
    closeLightbox();
    appData = null;
    revokeObjectUrls();
    pathContent.innerHTML = '';
    memoriesContent.innerHTML = '';
    try {
      localStorage.removeItem(STORAGE_KEY_LOCAL);
      sessionStorage.removeItem(STORAGE_KEY_SESSION);
    } catch (_) {}
    appShell.hidden = true;
    lockScreen.hidden = false;
    lockError.hidden = true;
    passwordInput.value = '';
    passwordInput.focus();
  }

  /* ---------- Challenge & Progress Math ---------- */

  function buildWeekTimeline(config, weeksData) {
    const ch = config.challenge;
    const start = parseIsoDate(ch.start_date);
    const end = parseIsoDate(ch.end_date);
    const weeklyTarget = Number(ch.weekly_target) || 3;

    const byStart = new Map();
    for (const w of weeksData || []) {
      byStart.set(w.week_start, w);
    }

    const now = new Date();
    const todayIso = toIsoDate(now);
    const todayDate = parseIsoDate(todayIso);

    const timeline = [];
    let cursor = start;
    let index = 1;

    while (cursor < end || (cursor.getTime() === end.getTime() && end.getDay() !== 1)) {
      const wsIso = toIsoDate(cursor);
      const weDate = addDays(cursor, 6);
      const weIso = toIsoDate(weDate);
      const raw = byStart.get(wsIso);

      let phase = 'future';
      if (weIso < todayIso) {
        phase = 'past';
      } else if (wsIso <= todayIso && todayIso <= weIso) {
        phase = 'current';
      }

      const normPerson = (p) => {
        const src = p || {};
        const status = src.status || 'active';
        const activities = Array.isArray(src.activities) ? src.activities : [];
        const done = typeof src.done === 'number' ? src.done : activities.length;
        return {
          done,
          status,
          reason: src.reason || '',
          activities,
        };
      };

      timeline.push({
        index,
        weekStart: wsIso,
        weekEnd: weIso,
        startDate: cursor,
        endDate: weDate,
        phase,
        note: raw ? raw.note || '' : '',
        sasha: normPerson(raw && raw.sasha),
        yulia: normPerson(raw && raw.yulia),
      });

      cursor = addDays(cursor, 7);
      index += 1;
    }

    // Compute stats per partner and combined team (excluding pause/sick weeks from denominator!)
    const partnerStats = {
      sasha: { doneTotal: 0, achieved: 0, planned: 0, activeWeeks: 0, pausedWeeks: 0, pastActiveWeeks: 0 },
      yulia: { doneTotal: 0, achieved: 0, planned: 0, activeWeeks: 0, pausedWeeks: 0, pastActiveWeeks: 0 },
    };

    for (const w of timeline) {
      if (w.phase === 'future') {
        // Count future workouts only if already logged early
        for (const k of ['sasha', 'yulia']) {
          if (w[k].done > 0) {
            partnerStats[k].doneTotal += w[k].done;
          }
        }
        continue;
      }

      for (const k of ['sasha', 'yulia']) {
        const p = w[k];
        const st = partnerStats[k];
        st.doneTotal += p.done;

        if (p.status === 'pause' || p.status === 'sick') {
          st.pausedWeeks += 1;
          continue;
        }

        st.activeWeeks += 1;
        if (w.phase === 'past') {
          st.pastActiveWeeks += 1;
          st.planned += weeklyTarget;
          st.achieved += p.done;
        } else if (w.phase === 'current') {
          // Avoid Monday-morning drop once at least one week is finished;
          // during Week 1 itself, measure against full weeklyTarget so progress feels honest.
          st.achieved += p.done;
          if (st.pastActiveWeeks > 0) {
            st.planned += Math.min(p.done, weeklyTarget);
          } else {
            st.planned += weeklyTarget;
          }
        }
      }
    }

    const calcPct = (achieved, planned) => {
      if (planned <= 0) return null;
      return Math.min(100, Math.round((achieved / planned) * 100));
    };

    partnerStats.sasha.percent = calcPct(partnerStats.sasha.achieved, partnerStats.sasha.planned);
    partnerStats.yulia.percent = calcPct(partnerStats.yulia.achieved, partnerStats.yulia.planned);

    const teamAchieved = partnerStats.sasha.achieved + partnerStats.yulia.achieved;
    const teamPlanned = partnerStats.sasha.planned + partnerStats.yulia.planned;
    const teamPercent = calcPct(teamAchieved, teamPlanned);
    const teamDoneTotal = partnerStats.sasha.doneTotal + partnerStats.yulia.doneTotal;
    const totalPausedSlots = partnerStats.sasha.pausedWeeks + partnerStats.yulia.pausedWeeks;

    const currentWeekObj = timeline.find((w) => w.phase === 'current');
    const elapsedWeeks = timeline.filter((w) => w.phase !== 'future').length;
    const daysToEnd = diffDays(todayDate, end);
    const daysToStart = diffDays(todayDate, start);

    return {
      timeline,
      partnerStats,
      teamPercent,
      teamDoneTotal,
      totalPausedSlots,
      weeklyTarget,
      currentWeekNum: currentWeekObj ? currentWeekObj.index : Math.min(elapsedWeeks, timeline.length),
      totalWeeks: timeline.length,
      daysToEnd,
      daysToStart,
    };
  }

  /* ---------- Render Tab 1: Путь ---------- */

  function renderPath() {
    const { config, weeks } = appData;
    const ch = config.challenge;
    const partners = config.partners;
    const stats = buildWeekTimeline(config, weeks);
    const targetPct = Number(ch.target_percent) || 75;

    // Countdown text
    let countdownText = '';
    if (stats.daysToStart > 0) {
      countdownText = `Старт через ${stats.daysToStart} ${pluralRu(stats.daysToStart, 'день', 'дня', 'дней')}`;
    } else if (stats.daysToEnd > 0) {
      countdownText = `${ch.countdown_label || 'До весны'}: ${stats.daysToEnd} ${pluralRu(stats.daysToEnd, 'день', 'дня', 'дней')}`;
    } else if (stats.daysToEnd === 0) {
      countdownText = 'Сегодня весенний финиш!';
    } else {
      countdownText = 'Весна наступила! Финиш пройден';
    }

    const pctVal = stats.teamPercent === null ? 0 : stats.teamPercent;
    const pctDisplay = stats.teamPercent === null ? '—' : `${pctVal}%`;
    const isOnTrack = stats.teamPercent !== null && pctVal >= targetPct;

    let statusPillHtml = '';
    if (stats.teamPercent === null) {
      statusPillHtml = `<span class="pill pill-yellow-soft">Пауза / старт</span>`;
    } else if (isOnTrack) {
      statusPillHtml = `<span class="pill pill-yellow">★ В ритме · выше ${targetPct}%</span>`;
    } else {
      statusPillHtml = `<span class="pill pill-orange">Ориентир ${targetPct}%</span>`;
    }

    const pauseChipHtml = stats.totalPausedSlots > 0
      ? `<span class="metric-chip">☕ Паузы учтены без штрафа</span>`
      : '';

    const heroHtml = `
      <article class="comic-card hero-card">
        <div class="hero-top">
          <span class="hero-dates">${escHtml(formatDateDot(ch.start_date))} — ${escHtml(formatDateDot(ch.end_date))}</span>
          <span class="pill countdown-pill">⏳ ${escHtml(countdownText)}</span>
        </div>

        <h2 class="hero-title">${escHtml(ch.title || 'Весенний командный челлендж')}</h2>

        <div class="score-row">
          <div>
            <div class="score-big">${escHtml(pctDisplay)}</div>
            <div class="score-caption">Командный ритм</div>
          </div>
          <div class="score-status">
            ${statusPillHtml}
          </div>
        </div>

        <div class="progress-wrap" aria-label="Прогресс команды: ${pctDisplay} при цели ${targetPct}%">
          <div class="threshold-flag" style="left: ${targetPct}%">Цель ${targetPct}%</div>
          <div class="progress-track">
            <div class="progress-fill ${pctVal === 0 ? 'is-zero' : ''} ${isOnTrack ? 'is-on-track' : ''}" style="width: ${pctVal}%"></div>
            <div class="threshold-line" style="left: ${targetPct}%"></div>
          </div>
        </div>

        <div class="hero-metrics">
          <span class="metric-chip">⚡ ${stats.teamDoneTotal} ${pluralRu(stats.teamDoneTotal, 'тренировка', 'тренировки', 'тренировок')}</span>
          <span class="metric-chip">📅 Неделя ${Math.max(1, stats.currentWeekNum)} из ${stats.totalWeeks}</span>
          <span class="metric-chip">🎯 По ${stats.weeklyTarget} в неделю</span>
          ${pauseChipHtml}
        </div>
      </article>
    `;

    // Weekly Grid
    const activeAndPast = stats.timeline.filter((w) => w.phase !== 'future');
    const futureWeeks = stats.timeline.filter((w) => w.phase === 'future');

    // Display active/past newest first so the current week is right at the top!
    const visibleActive = [...activeAndPast].reverse();
    const weeksToRender = showFutureWeeks
      ? [...visibleActive, ...futureWeeks]
      : visibleActive;

    const renderPersonWeekRow = (key, personData) => {
      const pName = (partners[key] && partners[key].name) || key;
      const dotColor = key === 'sasha' ? 'var(--blue)' : 'var(--orange)';
      const bonusCount = personData.status === 'active'
        ? Math.max(0, personData.done - stats.weeklyTarget)
        : 0;
      const bonusStarsHtml = bonusCount > 0
        ? `<span class="bonus-stars" title="Бонусные тренировки: +${bonusCount}" aria-label="Бонусные тренировки: +${bonusCount}">${'★'.repeat(bonusCount)}</span>`
        : '';

      let rightHtml = '';
      if (personData.status === 'pause') {
        const reason = personData.reason ? ` · ${escHtml(personData.reason)}` : '';
        rightHtml = `<span class="status-badge is-pause">☕ Пауза${reason}</span>`;
      } else if (personData.status === 'sick') {
        const reason = personData.reason ? ` · ${escHtml(personData.reason)}` : '';
        rightHtml = `<span class="status-badge is-sick">🍵 Болезнь${reason}</span>`;
      } else {
        const stamps = [];
        for (let i = 1; i <= stats.weeklyTarget; i += 1) {
          const isDone = i <= personData.done;
          stamps.push(
            `<span class="stamp is-${key} ${isDone ? 'is-done' : ''}" aria-label="${escHtml(pName)}: тренировка ${i} ${isDone ? 'выполнена' : 'впереди'}">${isDone ? '✓' : '·'}</span>`
          );
        }
        rightHtml = `<div class="stamps-row">${stamps.join('')}</div>`;
      }

      return `
        <div class="week-person-row">
          <div class="week-person-label">
            <span class="partner-dot" style="background: ${dotColor}; width: 10px; height: 10px;"></span>
            <span>${escHtml(pName)}</span>
            ${bonusStarsHtml}
          </div>
          ${rightHtml}
        </div>
      `;
    };

    const renderWeekCard = (w) => {
      let badgeHtml = '';
      if (w.phase === 'current') {
        badgeHtml = `<span class="pill pill-yellow">Сейчас</span>`;
      } else if (w.phase === 'past') {
        badgeHtml = `<span class="pill">Закрыта</span>`;
      } else {
        badgeHtml = `<span class="pill" style="opacity:0.75">Впереди</span>`;
      }

      return `
        <article class="comic-card week-card is-${w.phase}">
          <div class="week-head">
            <div class="week-title-group">
              <span class="week-num">Неделя ${w.index}</span>
              <span class="week-range">${escHtml(formatWeekRange(w.startDate, w.endDate))}</span>
            </div>
            ${badgeHtml}
          </div>

          <div class="week-partner-rows">
            ${renderPersonWeekRow('sasha', w.sasha)}
            ${renderPersonWeekRow('yulia', w.yulia)}
          </div>
        </article>
      `;
    };

    const futureToggleHtml = futureWeeks.length > 0
      ? `
        <button type="button" id="toggle-future-btn" class="comic-btn comic-btn-secondary toggle-future-btn">
          ${showFutureWeeks
            ? 'Скрыть будущие недели'
            : `Показать весь путь до весны (+${futureWeeks.length} ${pluralRu(futureWeeks.length, 'неделя', 'недели', 'недель')})`}
        </button>
      `
      : '';

    const weeksSectionHtml = `
      <div class="section-header">
        <h2 class="section-title">Сетка по неделям</h2>
      </div>
      <div class="weeks-list">
        ${weeksToRender.length ? weeksToRender.map(renderWeekCard).join('') : '<div class="comic-card empty-card">Недели появятся со старта челленджа!</div>'}
      </div>
      ${futureToggleHtml}
    `;

    pathContent.innerHTML = heroHtml + weeksSectionHtml;

    const toggleBtn = document.getElementById('toggle-future-btn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        showFutureWeeks = !showFutureWeeks;
        renderPath();
      });
    }
  }

  /* ---------- Render Tab 2: Воспоминания ---------- */

  function renderMemories() {
    const memories = appData.memories || [];
    memoriesCountBadge.textContent = String(memories.length);
    memoriesCountBadge.hidden = memories.length === 0;

    if (!memories.length) {
      memoriesContent.innerHTML = `
        <div class="comic-card empty-card">
          Воспоминания скоро появятся!
        </div>
      `;
      return;
    }

    memoriesContent.innerHTML = memories.map((mem) => {
      const photos = mem.photos || [];
      const countClass = `count-${Math.min(3, photos.length)}`;
      const photosHtml = photos.length
        ? `
          <div class="photo-grid ${countClass}">
            ${photos.map((p, idx) => `
              <button
                type="button"
                class="photo-tile"
                data-mem-id="${escHtml(mem.id)}"
                data-photo-idx="${idx}"
                aria-label="Открыть фото ${idx + 1}: ${escHtml(p.caption || mem.title)}"
              >
                <img src="${escHtml(p.url)}" alt="${escHtml(p.caption || mem.title)}" loading="lazy">
                <span class="photo-zoom-hint" aria-hidden="true">⤢</span>
              </button>
            `).join('')}
          </div>
        `
        : '';

      return `
        <article class="comic-card memory-card">
          <div class="memory-meta">
            <time class="memory-date" datetime="${escHtml(mem.date)}">${escHtml(formatDateRu(mem.date))}</time>
          </div>
          <h3 class="memory-title">${escHtml(mem.title)}</h3>
          ${mem.text ? `<p class="memory-text">${escHtml(mem.text)}</p>` : ''}
          ${photosHtml}
        </article>
      `;
    }).join('');

    memoriesContent.querySelectorAll('.photo-tile').forEach((tile) => {
      tile.addEventListener('click', () => {
        const memId = tile.dataset.memId;
        const pIdx = Number(tile.dataset.photoIdx) || 0;
        const mem = memories.find((m) => m.id === memId);
        if (mem && mem.photos && mem.photos.length) {
          openLightbox(mem, pIdx);
        }
      });
    });
  }

  /* ---------- Full-Screen Lightbox ---------- */

  function openLightbox(memory, startIndex) {
    lightboxPhotos = (memory.photos || []).map((p) => ({
      url: p.url,
      caption: p.caption || memory.title,
      meta: `${formatDateRu(memory.date)} · ${memory.title}`,
    }));
    lightboxIndex = Math.max(0, Math.min(startIndex, lightboxPhotos.length - 1));
    updateLightboxView();

    lightbox.hidden = false;
    document.body.style.overflow = 'hidden';
    requestAnimationFrame(() => {
      lightbox.classList.add('is-open');
    });
  }

  function updateLightboxView() {
    const item = lightboxPhotos[lightboxIndex];
    if (!item) return;
    lightboxImg.src = item.url;
    lightboxImg.alt = item.caption || '';
    lightboxCaption.textContent = item.caption || '';
    lightboxMeta.textContent = item.meta || '';
    lightboxCounter.textContent = `${lightboxIndex + 1} / ${lightboxPhotos.length}`;
    const multi = lightboxPhotos.length > 1;
    lightboxPrev.hidden = !multi;
    lightboxNext.hidden = !multi;
  }

  function stepLightbox(delta) {
    if (lightboxPhotos.length <= 1) return;
    lightboxIndex = (lightboxIndex + delta + lightboxPhotos.length) % lightboxPhotos.length;
    updateLightboxView();
  }

  function closeLightbox() {
    if (lightbox.hidden) return;
    lightbox.classList.remove('is-open');
    document.body.style.overflow = '';
    setTimeout(() => {
      if (!lightbox.classList.contains('is-open')) {
        lightbox.hidden = true;
        lightboxImg.removeAttribute('src');
      }
    }, 180);
  }

  /* ---------- Navigation & Render All ---------- */

  function switchTab(nextTab) {
    activeTab = nextTab;
    tabPath.hidden = activeTab !== 'path';
    tabMemories.hidden = activeTab !== 'memories';
    navBtns.forEach((btn) => {
      const isCurrent = btn.dataset.tab === activeTab;
      btn.classList.toggle('is-active', isCurrent);
      if (isCurrent) {
        btn.setAttribute('aria-current', 'page');
      } else {
        btn.removeAttribute('aria-current');
      }
    });
    window.scrollTo({ top: 0, behavior: 'instant' });
  }

  function renderAll() {
    const cfg = appData.config || {};
    appTitleEl.textContent = cfg.app_title || 'Трекер';
    renderPath();
    renderMemories();
    switchTab(activeTab);
  }

  /* ---------- Event Listeners ---------- */

  unlockForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const pw = passwordInput.value.trim();
    if (!pw) return;
    fetchAndUnlock(pw);
  });

  togglePassBtn.addEventListener('click', () => {
    const isPass = passwordInput.type === 'password';
    passwordInput.type = isPass ? 'text' : 'password';
    togglePassBtn.setAttribute('aria-pressed', String(isPass));
  });

  lockBtn.addEventListener('click', lockApp);

  navBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      if (target && target !== activeTab) {
        switchTab(target);
      }
    });
  });

  lightboxClose.addEventListener('click', closeLightbox);
  lightboxBackdrop.addEventListener('click', closeLightbox);
  lightboxPrev.addEventListener('click', () => stepLightbox(-1));
  lightboxNext.addEventListener('click', () => stepLightbox(1));

  lightboxStage.addEventListener('touchstart', (e) => {
    if (e.touches.length === 1) {
      touchStartX = e.touches[0].clientX;
    }
  }, { passive: true });

  lightboxStage.addEventListener('touchend', (e) => {
    if (touchStartX === null || !e.changedTouches.length) return;
    const dx = e.changedTouches[0].clientX - touchStartX;
    touchStartX = null;
    if (Math.abs(dx) > 42) {
      stepLightbox(dx < 0 ? 1 : -1);
    }
  }, { passive: true });

  document.addEventListener('keydown', (e) => {
    if (lightbox.hidden) return;
    if (e.key === 'Escape') closeLightbox();
    if (e.key === 'ArrowLeft') stepLightbox(-1);
    if (e.key === 'ArrowRight') stepLightbox(1);
  });

  /* ---------- Boot & PWA Registration ---------- */

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }

  // Try silent auto-unlock if password is saved on this device
  let savedPass = null;
  try {
    savedPass = sessionStorage.getItem(STORAGE_KEY_SESSION) || localStorage.getItem(STORAGE_KEY_LOCAL);
  } catch (_) {}

  if (savedPass) {
    fetchAndUnlock(savedPass, { silent: true });
  }
})();
