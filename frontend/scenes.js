/* Winnow — three.js scenes (hero object + 3D attack graph).
   Exposes window.WinnowScenes. Loaded before script.js. Requires global THREE. */
(function () {
  'use strict';

  var SEV_HEX = {
    dark: { CRITICAL: 0xd2686f, HIGH: 0xcc8b4e, MEDIUM: 0xbca85a, LOW: 0x7fa189 },
    light: { CRITICAL: 0xa8434b, HIGH: 0x91602c, MEDIUM: 0x7d6c22, LOW: 0x4a6b55 }
  };

  function metal(hex, extra) {
    var opts = { color: hex, metalness: 0.85, roughness: 0.32 };
    if (extra) for (var k in extra) opts[k] = extra[k];
    return new THREE.MeshStandardMaterial(opts);
  }

  function addLights(scene, dark) {
    scene.add(new THREE.HemisphereLight(dark ? 0x9ea3a2 : 0xffffff, dark ? 0x14171a : 0x9ea3a2, dark ? 0.5 : 0.85));
    var key = new THREE.DirectionalLight(0xffffff, dark ? 1.15 : 1.0);
    key.position.set(4, 6, 6);
    scene.add(key);
    var rim = new THREE.DirectionalLight(dark ? 0xc3c7c6 : 0xffffff, dark ? 0.7 : 0.35);
    rim.position.set(-6, 2, -4);
    scene.add(rim);
  }

  function makeRenderer(host) {
    var r = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    r.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    r.setSize(host.clientWidth || 600, host.clientHeight || 400);
    r.domElement.style.width = '100%';
    r.domElement.style.height = '100%';
    r.domElement.style.display = 'block';
    host.appendChild(r.domElement);
    return r;
  }

  /* Keep renderer + camera in step with the CONTAINER, not just the window.
     Returns a teardown fn. */
  function watchSize(host, renderer, camera) {
    function fit() {
      var w = host.clientWidth, h = host.clientHeight;
      if (!w || !h) return;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    window.addEventListener('resize', fit);
    var ro = window.ResizeObserver ? new ResizeObserver(fit) : null;
    if (ro) ro.observe(host);
    fit();
    return function () {
      window.removeEventListener('resize', fit);
      if (ro) ro.disconnect();
    };
  }

  /* ---------------- hero: slowly turning shield with orbit rings ---------------- */

  function createHero(host, opts) {
    if (!window.THREE || !host) return null;
    var dark = (opts && opts.theme) !== 'light';
    var renderer = makeRenderer(host);
    var scene = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(38, (host.clientWidth || 600) / (host.clientHeight || 340), 0.1, 100);
    camera.position.set(0.6, 0.5, 6.6);
    camera.lookAt(0, 0, 0);
    addLights(scene, dark);

    var group = new THREE.Group();

    /* Fit the object to the camera's actual frustum at z=0 so the outer ring
       (radius 1.85) clears the frame at any canvas aspect. */
    var OUTER = 1.95;
    function fitGroup() {
      var cw = host.clientWidth, ch = host.clientHeight;
      if (!cw || !ch) return;
      var dist = camera.position.length();
      var visH = 2 * Math.tan((camera.fov * Math.PI / 180) / 2) * dist;
      var visW = visH * (cw / ch);
      group.scale.setScalar(Math.min(visW, visH) / (2 * OUTER) * 0.92);
    }

    var shape = new THREE.Shape();
    shape.moveTo(0, 1.25);
    shape.bezierCurveTo(0.85, 1.2, 1.0, 0.95, 1.0, 0.55);
    shape.lineTo(1.0, -0.15);
    shape.bezierCurveTo(1.0, -0.95, 0.5, -1.25, 0, -1.5);
    shape.bezierCurveTo(-0.5, -1.25, -1.0, -0.95, -1.0, -0.15);
    shape.lineTo(-1.0, 0.55);
    shape.bezierCurveTo(-1.0, 0.95, -0.85, 1.2, 0, 1.25);

    var shield = new THREE.Mesh(
      new THREE.ExtrudeGeometry(shape, { depth: 0.22, bevelEnabled: true, bevelSize: 0.045, bevelThickness: 0.05, bevelSegments: 4, curveSegments: 24 }),
      metal(dark ? 0xd4d8d7 : 0x8e9391, { roughness: 0.24, emissive: dark ? 0x3a3f42 : 0x000000, emissiveIntensity: dark ? 0.5 : 0 })
    );
    shield.scale.set(0.92, 0.92, 1);
    group.add(shield);

    var ring = new THREE.Mesh(new THREE.TorusGeometry(1.55, 0.012, 8, 120), metal(dark ? 0xc3c7c6 : 0x5b6062, { roughness: 0.5 }));
    ring.rotation.x = Math.PI * 0.42;
    group.add(ring);

    var ring2 = new THREE.Mesh(new THREE.TorusGeometry(1.85, 0.008, 8, 120), metal(dark ? 0x9ea3a2 : 0x6a6f71, { roughness: 0.6 }));
    ring2.rotation.x = Math.PI * 0.58;
    ring2.rotation.y = 0.3;
    group.add(ring2);

    var dots = new THREE.Group();
    for (var i = 0; i < 26; i++) {
      var a = (i / 26) * Math.PI * 2;
      var rr = 1.55 + (i % 3) * 0.16;
      var flagged = i % 7 === 0;
      var d = new THREE.Mesh(
        new THREE.SphereGeometry(0.028, 10, 10),
        metal(flagged ? (dark ? 0xd2686f : 0xa8434b) : (dark ? 0x9ea3a2 : 0x6a6f71), { roughness: 0.4 })
      );
      d.position.set(Math.cos(a) * rr, Math.sin(a) * rr * 0.42, Math.sin(a) * rr * 0.5);
      dots.add(d);
    }
    group.add(dots);
    scene.add(group);

    var raf;
    var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    function tick() {
      var t = performance.now() / 1000;
      if (!reduce) {
        group.rotation.y = Math.sin(t * 0.28) * 0.5 + 0.35;
        group.rotation.x = Math.sin(t * 0.19) * 0.12;
        ring.rotation.z = t * 0.18;
        ring2.rotation.z = -t * 0.12;
        dots.rotation.y = t * 0.22;
      }
      renderer.render(scene, camera);
      raf = requestAnimationFrame(tick);
    }
    tick();

    var unwatchSize = watchSize(host, renderer, camera);
    fitGroup();
    var refit = function () { fitGroup(); };
    window.addEventListener('resize', refit);
    var groupRo = window.ResizeObserver ? new ResizeObserver(refit) : null;
    if (groupRo) groupRo.observe(host);

    return {
      dispose: function () {
        cancelAnimationFrame(raf);
        unwatchSize();
        window.removeEventListener('resize', refit);
        if (groupRo) groupRo.disconnect();
        if (renderer.domElement.parentNode) renderer.domElement.parentNode.removeChild(renderer.domElement);
        renderer.dispose();
      }
    };
  }

  /* ---------------- attack graph: three columns in real 3D space ---------------- */

  function createGraph(host, opts) {
    if (!window.THREE || !host) return null;
    opts = opts || {};
    var findings = opts.findings || [];
    var groups = opts.groups || [];
    var techniques = opts.techniques || [];
    var dark = opts.theme !== 'light';
    var sev = SEV_HEX[dark ? 'dark' : 'light'];
    var showIdent = opts.showIdentities !== false;
    var showMitre = opts.showMitre !== false;
    var spinning = opts.autoOrbit !== false;
    var onSelect = opts.onSelect || function () {};

    var renderer = makeRenderer(host);
    var scene = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(45, (host.clientWidth || 700) / (host.clientHeight || 560), 0.1, 200);
    addLights(scene, dark);

    var world = new THREE.Group();
    scene.add(world);

    var COL = { ident: -7, vuln: 0, mitre: 7 };
    var SPAN = 9;

    var ordered = [];
    groups.forEach(function (g) { g.ids.forEach(function (id) { ordered.push(id); }); });

    var pos = {};
    ordered.forEach(function (id, i) {
      var f = (i / Math.max(1, ordered.length - 1)) - 0.5;
      pos[id] = new THREE.Vector3(COL.vuln, -f * SPAN, Math.sin(i * 1.7) * 1.4);
    });

    function meanY(ids) {
      var ys = ids.map(function (id) { return pos[id] ? pos[id].y : 0; });
      return ys.reduce(function (a, b) { return a + b; }, 0) / Math.max(1, ys.length);
    }

    var identPos = {};
    groups.forEach(function (g, gi) {
      identPos[g.name] = new THREE.Vector3(COL.ident, meanY(g.ids), (gi % 2 ? 1 : -1) * 0.8);
    });

    var mitrePos = {};
    techniques.forEach(function (m, mi) {
      var ids = findings.filter(function (f) { return f.mitre.indexOf(m.id) >= 0; }).map(function (f) { return f.id; });
      mitrePos[m.id] = new THREE.Vector3(COL.mitre, meanY(ids), ((mi % 3) - 1) * 1.2);
    });

    var dimLine = new THREE.LineBasicMaterial({ color: dark ? 0x6a6f71 : 0x8e9391, transparent: true, opacity: 0.55 });

    function curveLine(a, b, mat) {
      var mid = a.clone().add(b).multiplyScalar(0.5);
      mid.z += 1.1;
      var pts = new THREE.QuadraticBezierCurve3(a, mid, b).getPoints(28);
      return new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), mat);
    }

    if (showIdent) {
      groups.forEach(function (g) {
        var box = new THREE.Mesh(new THREE.BoxGeometry(2.6, 0.8, 0.5), metal(dark ? 0x2f3437 : 0xcfd2d1, { roughness: 0.45 }));
        box.position.copy(identPos[g.name]);
        world.add(box);
        var edges = new THREE.LineSegments(new THREE.EdgesGeometry(box.geometry), new THREE.LineBasicMaterial({ color: dark ? 0xc3c7c6 : 0x4e5356 }));
        edges.position.copy(box.position);
        world.add(edges);
        g.ids.forEach(function (id) {
          var f = findings.find(function (x) { return x.id === id; });
          if (!f) return;
          world.add(curveLine(identPos[g.name], pos[id], new THREE.LineBasicMaterial({ color: sev[f.severity], transparent: true, opacity: 0.65 })));
        });
      });
    }

    var picks = [];
    findings.forEach(function (f) {
      if (!pos[f.id]) return;
      var r = f.severity === 'CRITICAL' ? 0.34 : f.severity === 'HIGH' ? 0.29 : 0.25;
      var node = new THREE.Mesh(
        new THREE.SphereGeometry(r, 24, 24),
        metal(sev[f.severity], { roughness: 0.3, emissive: sev[f.severity], emissiveIntensity: dark ? 0.22 : 0.05 })
      );
      node.position.copy(pos[f.id]);
      node.userData.id = f.id;
      world.add(node);
      picks.push(node);

      var halo = new THREE.Mesh(
        new THREE.RingGeometry(r + 0.12, r + 0.16, 32),
        new THREE.MeshBasicMaterial({ color: sev[f.severity], transparent: true, opacity: 0.4, side: THREE.DoubleSide })
      );
      halo.position.copy(pos[f.id]);
      world.add(halo);
    });

    var octs = [];
    if (showMitre) {
      techniques.forEach(function (m) {
        var oct = new THREE.Mesh(new THREE.OctahedronGeometry(0.36), metal(dark ? 0xb7bbba : 0x6a6f71, { roughness: 0.35 }));
        oct.position.copy(mitrePos[m.id]);
        world.add(oct);
        octs.push(oct);
        findings.filter(function (f) { return f.mitre.indexOf(m.id) >= 0; }).forEach(function (f) {
          if (pos[f.id]) world.add(curveLine(pos[f.id], mitrePos[m.id], dimLine));
        });
      });
    }

    var grid = new THREE.GridHelper(26, 26, dark ? 0x2b2f32 : 0xb3b7b6, dark ? 0x23272a : 0xbfc3c2);
    grid.position.y = -SPAN / 2 - 1.6;
    grid.material.transparent = true;
    grid.material.opacity = 0.5;
    world.add(grid);

    var HOME = { theta: -0.42, phi: 1.32, dist: 20 };
    var cam = { theta: HOME.theta, phi: HOME.phi, dist: HOME.dist };

    function applyCam() {
      camera.position.set(
        cam.dist * Math.sin(cam.phi) * Math.sin(cam.theta),
        cam.dist * Math.cos(cam.phi),
        cam.dist * Math.sin(cam.phi) * Math.cos(cam.theta)
      );
      camera.lookAt(0, 0, 0);
    }
    applyCam();

    var el = renderer.domElement;
    var dragging = false, lastX = 0, lastY = 0, moved = 0;

    function onDown(e) { dragging = true; moved = 0; lastX = e.clientX; lastY = e.clientY; host.classList.add('dragging'); }
    function onMove(e) {
      if (!dragging) return;
      var dx = e.clientX - lastX, dy = e.clientY - lastY;
      moved += Math.abs(dx) + Math.abs(dy);
      lastX = e.clientX; lastY = e.clientY;
      cam.theta -= dx * 0.005;
      cam.phi = Math.max(0.35, Math.min(2.6, cam.phi - dy * 0.005));
      applyCam();
    }
    function onUp() { dragging = false; host.classList.remove('dragging'); }
    function onWheel(e) { e.preventDefault(); cam.dist = Math.max(9, Math.min(40, cam.dist + e.deltaY * 0.02)); applyCam(); }

    var ray = new THREE.Raycaster(), ndc = new THREE.Vector2();
    function onClick(e) {
      if (moved > 6) return;
      var r = el.getBoundingClientRect();
      ndc.x = ((e.clientX - r.left) / r.width) * 2 - 1;
      ndc.y = -((e.clientY - r.top) / r.height) * 2 + 1;
      ray.setFromCamera(ndc, camera);
      var hit = ray.intersectObjects(picks)[0];
      if (hit && hit.object.userData.id) onSelect(hit.object.userData.id);
    }

    el.addEventListener('mousedown', onDown);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    el.addEventListener('wheel', onWheel, { passive: false });
    el.addEventListener('click', onClick);

    var raf;
    var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    function tick() {
      if (spinning && !dragging && !reduce) { cam.theta += 0.0012; applyCam(); }
      if (!reduce) octs.forEach(function (o) { o.rotation.y += 0.006; });
      renderer.render(scene, camera);
      raf = requestAnimationFrame(tick);
    }
    tick();

    var unwatch = watchSize(host, renderer, camera);

    return {
      resetCamera: function () { cam.theta = HOME.theta; cam.phi = HOME.phi; cam.dist = HOME.dist; applyCam(); },
      setAutoOrbit: function (on) { spinning = !!on; },
      dispose: function () {
        cancelAnimationFrame(raf);
        el.removeEventListener('mousedown', onDown);
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
        el.removeEventListener('wheel', onWheel);
        el.removeEventListener('click', onClick);
        unwatch();
        if (el.parentNode) el.parentNode.removeChild(el);
        renderer.dispose();
      }
    };
  }

  window.WinnowScenes = { createHero: createHero, createGraph: createGraph };
})();
