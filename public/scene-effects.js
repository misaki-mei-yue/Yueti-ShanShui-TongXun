/* A quiet landscape layer. No input is intercepted and no network is used. */
(() => {
  'use strict';

  if (window.YuetiScene && typeof window.YuetiScene.destroy === 'function') {
    window.YuetiScene.destroy();
  }

  const FRAME_MS = 1000 / 30;
  const reducedQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const initialReducedMotion = reducedQuery.matches;
  const layers = [];
  const makeLayer = id => {
    let canvas = document.getElementById(id);
    const created = !canvas;
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = id;
      document.body.appendChild(canvas);
    }
    const prior = {
      style: canvas.getAttribute('style'),
      width: canvas.getAttribute('width'),
      height: canvas.getAttribute('height'),
      hidden: canvas.getAttribute('aria-hidden')
    };
    canvas.setAttribute('aria-hidden', 'true');
    Object.assign(canvas.style, {
      position: 'fixed', inset: '0', width: '100%', height: '100%',
      pointerEvents: 'none', zIndex: '1', contain: 'strict'
    });
    layers.push({ canvas, created, prior });
    return { canvas, context: canvas.getContext('2d', { alpha: true }) };
  };

  const water = makeLayer('water-canvas');
  const weather = makeLayer('weather-canvas');
  const streams = Array.from({ length: 26 }, (_, i) => ({
    depth: (i + 1) / 27,
    phase: Math.random() * Math.PI * 2,
    offset: Math.random(),
    length: .1 + Math.random() * .18,
    speed: .6 + Math.random() * .7
  }));

  let viewportWidth = 0;
  let viewportHeight = 0;
  let pixelRatio = 1;
  let particles = [];
  let ripples = [];
  let weatherMode = 'snow';
  let motionEnabled = !initialReducedMotion;
  let explicitMotionChoice = false;
  let destroyed = false;
  let pageSuspended = false;
  let offscreen = false;
  let frameRequest = null;
  let lastFrame = null;
  let sceneTime = 0;
  let resizePending = false;

  const visible = () => !document.hidden && !pageSuspended && !offscreen;
  const random = (min, max) => min + Math.random() * (max - min);
  const particleCount = () => Math.min(50, Math.max(40, Math.round(viewportWidth * viewportHeight / 24000)));

  function createParticle(fromTop = false) {
    const depth = Math.random();
    return {
      x: random(-20, viewportWidth + 20),
      y: fromTop ? random(-70, -10) : random(-30, viewportHeight + 20),
      depth, phase: random(0, Math.PI * 2),
      size: weatherMode === 'petals' ? 4 + depth * 4 : .7 + depth * 1.9,
      fall: weatherMode === 'petals' ? 14 + depth * 27 : 9 + depth * 25,
      drift: random(-8, 10),
      rotation: random(0, Math.PI * 2),
      spin: random(-.7, .7),
      blush: Math.random()
    };
  }

  function populate() {
    particles = weatherMode === 'none' ? [] : Array.from({ length: particleCount() }, () => createParticle());
  }

  function clearLayer(layer) {
    if (layer.context) layer.context.clearRect(0, 0, viewportWidth, viewportHeight);
  }

  function sizeLayers() {
    const oldWidth = viewportWidth;
    const oldHeight = viewportHeight;
    viewportWidth = Math.max(1, window.innerWidth);
    viewportHeight = Math.max(1, window.innerHeight);
    pixelRatio = Math.min(1.5, Math.max(1, window.devicePixelRatio || 1));
    layers.forEach(({ canvas }) => {
      canvas.width = Math.round(viewportWidth * pixelRatio);
      canvas.height = Math.round(viewportHeight * pixelRatio);
    });
    [water, weather].forEach(layer => {
      if (layer.context) layer.context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    });
    if (oldWidth && oldHeight) {
      particles.forEach(particle => {
        particle.x *= viewportWidth / oldWidth;
        particle.y *= viewportHeight / oldHeight;
      });
      ripples.forEach(ripple => {
        ripple.x *= viewportWidth / oldWidth;
        ripple.y *= viewportHeight / oldHeight;
      });
      if (weatherMode !== 'none') {
        while (particles.length < particleCount()) particles.push(createParticle());
        particles.length = particleCount();
      }
    } else {
      populate();
    }
    resizePending = false;
    draw();
  }

  function drawWater() {
    const ctx = water.context;
    if (!ctx) return;
    clearLayer(water);
    const horizon = viewportHeight * .65;
    const waterHeight = viewportHeight - horizon;
    ctx.save();
    ctx.beginPath();
    ctx.rect(0, horizon, viewportWidth, waterHeight);
    ctx.clip();

    // Long, uneven glints suggest a current without making the painting shimmer.
    streams.forEach((stream, index) => {
      const depth = stream.depth * stream.depth;
      const y = horizon + depth * waterHeight;
      const progress = sceneTime * (1.2 + depth * 2.2) * stream.speed;
      const length = viewportWidth * stream.length * (.48 + depth);
      const x = ((stream.offset * viewportWidth + progress) % (viewportWidth + length)) - length * .5;
      const phase = stream.phase + sceneTime * .16;
      const amplitude = .6 + depth * 2.2;
      const fade = .045 + depth * .075;

      ctx.lineWidth = .5 + depth * .45;
      ctx.strokeStyle = index % 3 === 0 ? `rgba(107, 92, 72, ${fade})` : `rgba(250, 244, 228, ${fade * 2.2})`;
      ctx.beginPath();
      for (let sample = 0; sample <= 24; sample += 1) {
        const fraction = sample / 24;
        const px = x + fraction * length;
        const py = y + Math.sin(fraction * Math.PI * 3.5 + phase) * amplitude
          + Math.sin(fraction * Math.PI * 7 - phase) * amplitude * .25;
        if (sample === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.stroke();
    });
    ctx.restore();

    // Elliptical wave crests and their dark underside have the weight of water.
    ripples.forEach(ripple => {
      const duration = 3.1;
      const life = ripple.age / duration;
      const disappear = Math.pow(Math.max(0, 1 - life), 1.5);
      const radius = 8 + ripple.age * 67;
      const perspective = .34 + Math.min(.19, ripple.y / viewportHeight * .19);
      ctx.save();
      ctx.translate(ripple.x, ripple.y);
      ctx.scale(1, perspective);
      for (let crest = 0; crest < 3; crest += 1) {
        const ringRadius = radius - crest * 15;
        if (ringRadius < 4) continue;
        const opacity = disappear * (.27 - crest * .055);
        ctx.lineWidth = 1.2 + crest * .12;
        ctx.strokeStyle = `rgba(100, 83, 63, ${opacity})`;
        ctx.beginPath();
        ctx.ellipse(0, 1.8, ringRadius, ringRadius, -.04, .08, Math.PI * 2 - .08);
        ctx.stroke();
        ctx.strokeStyle = `rgba(255, 246, 222, ${opacity * 1.65})`;
        ctx.beginPath();
        ctx.ellipse(0, -1.2, ringRadius - 1, ringRadius - 1, -.04, Math.PI * 1.05, Math.PI * 1.9);
        ctx.stroke();
      }
      if (life < .35) {
        const glow = ctx.createRadialGradient(0, 0, 0, 0, 0, radius);
        glow.addColorStop(0, `rgba(250, 238, 211, ${disappear * .055})`);
        glow.addColorStop(1, 'rgba(250, 238, 211, 0)');
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(0, 0, radius, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.restore();
    });
  }

  function drawWeather() {
    const ctx = weather.context;
    if (!ctx) return;
    clearLayer(weather);
    if (weatherMode === 'none') return;
    particles.forEach(particle => {
      ctx.save();
      if (weatherMode === 'snow') {
        const opacity = .24 + particle.depth * .42;
        // A faint underside makes white snow readable on pale rice paper.
        ctx.fillStyle = `rgba(113, 97, 80, ${.12 + particle.depth * .14})`;
        ctx.beginPath();
        ctx.arc(particle.x + .35, particle.y + .5, particle.size + .35, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = `rgba(255, 250, 238, ${opacity})`;
        ctx.beginPath();
        ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
        ctx.fill();
      } else {
        ctx.translate(particle.x, particle.y);
        ctx.rotate(particle.rotation);
        const tilt = .3 + .7 * Math.abs(Math.cos(sceneTime * .5 + particle.phase));
        ctx.scale(tilt, 1);
        ctx.globalAlpha = .3 + particle.depth * .35;
        ctx.fillStyle = particle.blush > .5 ? '#d6a5a4' : '#edd0c1';
        const size = particle.size;
        ctx.beginPath();
        ctx.moveTo(0, -size);
        ctx.bezierCurveTo(size * .85, -size * .75, size * .7, size * .6, 0, size);
        ctx.bezierCurveTo(-size * .32, size * .45, -size * .9, -size * .45, 0, -size);
        ctx.fill();
        ctx.strokeStyle = 'rgba(144, 89, 86, .26)';
        ctx.lineWidth = .55;
        ctx.beginPath();
        ctx.moveTo(0, -size * .68);
        ctx.quadraticCurveTo(-size * .1, 0, 0, size * .65);
        ctx.stroke();
      }
      ctx.restore();
    });
  }

  function draw() {
    drawWater();
    drawWeather();
  }

  function update(delta) {
    sceneTime += delta;
    const wind = Math.sin(sceneTime * .18) * 7;
    particles.forEach(particle => {
      const breeze = Math.sin(sceneTime * .55 + particle.phase) * (4 + particle.depth * 8);
      particle.x += (wind + breeze + particle.drift + (weatherMode === 'petals' ? 10 : 0)) * delta;
      particle.y += particle.fall * delta;
      particle.rotation += particle.spin * delta;
      if (particle.y > viewportHeight + 25) Object.assign(particle, createParticle(true));
      if (particle.x < -35) particle.x = viewportWidth + 30;
      if (particle.x > viewportWidth + 35) particle.x = -30;
    });
    ripples.forEach(ripple => { ripple.age += delta; });
    ripples = ripples.filter(ripple => ripple.age < 3.1);
  }

  function cancelFrame() {
    if (frameRequest !== null) window.cancelAnimationFrame(frameRequest);
    frameRequest = null;
    lastFrame = null;
  }

  function frame(now) {
    frameRequest = null;
    if (destroyed || !motionEnabled || !visible()) {
      lastFrame = null;
      return;
    }
    if (lastFrame === null) lastFrame = now;
    const elapsed = now - lastFrame;
    if (elapsed + .00001 >= FRAME_MS) {
      // Time belongs to visible frames, so returning to a tab never skips seasons.
      update(Math.min(elapsed / 1000, .05));
      lastFrame = now;
      if (resizePending) sizeLayers(); else draw();
    }
    frameRequest = window.requestAnimationFrame(frame);
  }

  function resume() {
    if (destroyed) return;
    if (resizePending && visible()) sizeLayers();
    if (!motionEnabled || !visible()) {
      cancelFrame();
      return;
    }
    if (frameRequest === null && (water.context || weather.context)) {
      lastFrame = null;
      frameRequest = window.requestAnimationFrame(frame);
    }
  }

  function publishState() {
    window.dispatchEvent(new CustomEvent('yueti:scenechange', { detail: getState() }));
  }

  function getState() {
    return Object.freeze({
      weather: weatherMode, motion: motionEnabled,
      rippleCount: ripples.length, particleCount: particles.length,
      running: frameRequest !== null && motionEnabled && visible() && !destroyed,
      reducedMotion: reducedQuery.matches, destroyed
    });
  }

  function setWeather(mode) {
    if (destroyed) return getState();
    if (!['snow', 'petals', 'none'].includes(mode)) throw new RangeError('Weather must be snow, petals, or none.');
    if (mode !== weatherMode) {
      weatherMode = mode;
      populate();
      drawWeather();
      publishState();
    }
    resume();
    return getState();
  }

  function setMotion(enabled) {
    if (destroyed) return getState();
    explicitMotionChoice = true;
    motionEnabled = Boolean(enabled);
    if (!motionEnabled) {
      cancelFrame();
      ripples = [];
      draw();
    } else {
      resume();
    }
    publishState();
    return getState();
  }

  function ripple(x, y) {
    if (destroyed || !motionEnabled || !visible() || !Number.isFinite(x) || !Number.isFinite(y)) return false;
    if (x < 0 || y < 0 || x > viewportWidth || y > viewportHeight) return false;
    ripples.push({ x, y, age: 0 });
    // A bounded pool protects quick typing and repeated clicks from growing work.
    if (ripples.length > 9) ripples.shift();
    resume();
    return true;
  }

  function pointerDown(event) {
    if (event.isPrimary === false || (event.button !== undefined && event.button !== 0)) return;
    ripple(event.clientX, event.clientY);
  }

  function resize() {
    resizePending = true;
    if (!visible()) return;
    if (motionEnabled) resume(); else sizeLayers();
  }

  function visibilityChange() {
    if (!visible()) cancelFrame(); else resume();
  }

  function pageHide() { pageSuspended = true; cancelFrame(); }
  function pageShow() { pageSuspended = false; resume(); }

  function reducedMotionChange() {
    if (explicitMotionChoice || destroyed) return;
    motionEnabled = !reducedQuery.matches;
    if (!motionEnabled) {
      cancelFrame();
      ripples = [];
      draw();
    } else resume();
    publishState();
  }

  const observer = typeof window.IntersectionObserver === 'function'
    ? new IntersectionObserver(entries => {
      if (destroyed) return;
      offscreen = !entries[0].isIntersecting;
      visibilityChange();
    }) : null;

  function destroy() {
    if (destroyed) return;
    destroyed = true;
    cancelFrame();
    observer?.disconnect();
    window.removeEventListener('resize', resize);
    window.removeEventListener('pointerdown', pointerDown);
    window.removeEventListener('pagehide', pageHide);
    window.removeEventListener('pageshow', pageShow);
    document.removeEventListener('visibilitychange', visibilityChange);
    if (typeof reducedQuery.removeEventListener === 'function') reducedQuery.removeEventListener('change', reducedMotionChange);
    else if (typeof reducedQuery.removeListener === 'function') reducedQuery.removeListener(reducedMotionChange);
    clearLayer(water);
    clearLayer(weather);
    layers.forEach(({ canvas, created, prior }) => {
      if (created) canvas.remove();
      else Object.entries({ style: prior.style, width: prior.width, height: prior.height, 'aria-hidden': prior.hidden }).forEach(([name, value]) => {
        if (value === null) canvas.removeAttribute(name); else canvas.setAttribute(name, value);
      });
    });
    particles = [];
    ripples = [];
  }

  window.YuetiScene = Object.freeze({ setWeather, setMotion, ripple, getState, destroy });
  window.addEventListener('resize', resize, { passive: true });
  window.addEventListener('pointerdown', pointerDown, { passive: true });
  window.addEventListener('pagehide', pageHide);
  window.addEventListener('pageshow', pageShow);
  document.addEventListener('visibilitychange', visibilityChange);
  if (typeof reducedQuery.addEventListener === 'function') reducedQuery.addEventListener('change', reducedMotionChange);
  else if (typeof reducedQuery.addListener === 'function') reducedQuery.addListener(reducedMotionChange);
  sizeLayers();
  observer?.observe(water.canvas);
  resume();
  window.dispatchEvent(new Event('yueti-scene-ready'));
})();
