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

  /* A billboarded text label as a canvas-textured sprite. */
  function makeLabel(text, dark) {
    var pad = 8, font = '600 30px Inter, system-ui, sans-serif';
    var c = document.createElement('canvas'), g = c.getContext('2d');
    g.font = font;
    var w = Math.ceil(g.measureText(text).width) + pad * 2;
    c.width = w; c.height = 44;
    g.font = font;
    g.fillStyle = dark ? 'rgba(23,26,28,0.82)' : 'rgba(255,255,255,0.9)';
    g.fillRect(0, 0, w, 44);
    g.fillStyle = dark ? '#e9ebea' : '#1f2225';
    g.textBaseline = 'middle';
    g.fillText(text, pad, 24);
    var tex = new THREE.CanvasTexture(c);
    tex.minFilter = THREE.LinearFilter;
    var spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
    spr.scale.set(w / 44 * 0.9, 0.9, 1);
    return spr;
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

  /* ---------------- IAM permission graph in real 3D space ----------------
     Consumes the backend's `visualization.permission_graph`: identity / policy
     nodes, has_policy / member_of / can_assume edges, and escalation paths.
     Falls back to a findings-only view when no permission graph is supplied
     (offline demo). */

  function createGraph(host, opts) {
    if (!window.THREE || !host) return null;
    opts = opts || {};
    var pg = opts.permissionGraph && opts.permissionGraph.nodes && opts.permissionGraph.nodes.length
      ? opts.permissionGraph : null;
    var findings = opts.findings || [];
    var dark = opts.theme !== 'light';
    var sev = SEV_HEX[dark ? 'dark' : 'light'];
    var showIdent = opts.showIdentities !== false;
    var showMitre = opts.showMitre !== false;   // "MITRE" chip now toggles policy nodes
    var spinning = opts.autoOrbit !== false;
    var onSelect = opts.onSelect || function () {};

    var renderer = makeRenderer(host);
    var scene = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(45, (host.clientWidth || 700) / (host.clientHeight || 560), 0.1, 200);
    addLights(scene, dark);
    var world = new THREE.Group();
    scene.add(world);

    var COL = { ident: -7, mid: 0, policy: 7 };
    var SPAN = 10;

    function curveLine(a, b, mat) {
      var mid = a.clone().add(b).multiplyScalar(0.5);
      mid.z += 1.1;
      var pts = new THREE.QuadraticBezierCurve3(a, mid, b).getPoints(24);
      return new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), mat);
    }
    function riskHex(level) {
      return ({ critical: sev.CRITICAL, high: sev.HIGH, medium: sev.MEDIUM, low: sev.LOW })[level]
        || (dark ? 0x6a6f71 : 0x8e9391);
    }
    function findingFor(name) {
      var f = findings.find(function (x) { return x.resource === name; });
      return f ? f.id : (findings[0] && findings[0].id);
    }

    var picks = [];
    var grid = new THREE.GridHelper(28, 28, dark ? 0x2b2f32 : 0xb3b7b6, dark ? 0x23272a : 0xbfc3c2);
    grid.position.y = -SPAN / 2 - 1.8;
    grid.material.transparent = true; grid.material.opacity = 0.5;
    world.add(grid);

    if (pg) {
      var nodes = pg.nodes.slice();
      var identNodes = nodes.filter(function (n) { return n.type === 'user' || n.type === 'role' || n.type === 'group'; });
      var polNodes = showMitre ? nodes.filter(function (n) { return n.type === 'policy'; }) : [];
      var escByNode = {};
      (pg.escalation_paths || []).forEach(function (e) {
        (e.path || []).forEach(function (nid) { escByNode[nid] = true; });
        escByNode[e.affected_identity] = true;
      });
      // A policy is "hot" if an escalation-involved identity holds it.
      (pg.links || []).forEach(function (l) {
        if (l.relationship === 'has_policy' && escByNode[l.source]) escByNode[l.target] = true;
      });

      var pos = {};
      function place(list, x) {
        var span = Math.max(1, list.length - 1);
        list.forEach(function (n, i) {
          var t = list.length === 1 ? 0.5 : i / span;
          pos[n.id] = new THREE.Vector3(x, SPAN / 2 - t * SPAN, Math.sin(i * 1.7) * 1.6);
        });
      }
      place(identNodes, COL.ident);
      place(polNodes, COL.policy);

      var edgeMat = {
        has_policy: function (n) { return new THREE.LineBasicMaterial({ color: riskHex(n && n.risk_level), transparent: true, opacity: 0.5 }); },
        member_of: function () { return new THREE.LineBasicMaterial({ color: dark ? 0x9ea3a2 : 0x5b6062, transparent: true, opacity: 0.55 }); },
        can_assume: function () { return new THREE.LineBasicMaterial({ color: 0x5fa8d3, transparent: true, opacity: 0.7 }); }
      };
      var polById = {};
      polNodes.forEach(function (n) { polById[n.id] = n; });
      (pg.links || []).forEach(function (l) {
        var a = pos[l.source], b = pos[l.target];
        if (!a || !b) return;
        var mk = edgeMat[l.relationship];
        if (!mk) return;
        world.add(curveLine(a, b, mk(polById[l.target])));
      });

      // escalation paths — thicker red poly-lines along path node ids
      (pg.escalation_paths || []).forEach(function (e) {
        var pts = (e.path || []).map(function (nid) { return pos[nid]; }).filter(Boolean);
        for (var i = 0; i + 1 < pts.length; i++) {
          world.add(curveLine(pts[i], pts[i + 1], new THREE.LineBasicMaterial({ color: sev.CRITICAL, transparent: true, opacity: 0.85 })));
        }
      });

      identNodes.forEach(function (n) {
        var unreachable = n.type === 'role' && n.reachable === false;
        var box = new THREE.Mesh(
          new THREE.BoxGeometry(2.6, 0.82, 0.5),
          metal(dark ? 0x2f3437 : 0xcfd2d1, { roughness: 0.45, transparent: unreachable, opacity: unreachable ? 0.35 : 1 })
        );
        box.position.copy(pos[n.id]);
        box.userData.id = findingFor(n.name);
        box.userData.label = n.type.toUpperCase() + '  ' + n.name + (unreachable ? '  (service-only, filtered)' : '');
        world.add(box);
        picks.push(box);
        var col = escByNode[n.id] ? sev.CRITICAL : riskHex(n.risk_level);
        var edges = new THREE.LineSegments(new THREE.EdgesGeometry(box.geometry),
          new THREE.LineBasicMaterial({ color: col, transparent: unreachable, opacity: unreachable ? 0.4 : 1 }));
        edges.position.copy(pos[n.id]);
        world.add(edges);
        var lbl = makeLabel(n.name, dark);
        lbl.position.copy(pos[n.id]); lbl.position.y += 0.85;
        world.add(lbl);
      });

      polNodes.forEach(function (n) {
        var hot = escByNode[n.id] || n.risk_level === 'critical' || n.risk_level === 'high';
        var hex = hot ? sev.CRITICAL : (dark ? 0x9ea3a2 : 0x6a6f71);
        var s = new THREE.Mesh(new THREE.SphereGeometry(hot ? 0.32 : 0.24, 22, 22),
          metal(hex, { roughness: 0.35, emissive: hot ? hex : 0x000000, emissiveIntensity: hot ? 0.25 : 0 }));
        s.position.copy(pos[n.id]);
        s.userData.id = findingFor(n.name);
        s.userData.label = 'POLICY  ' + n.name;
        world.add(s);
        picks.push(s);
        var plbl = makeLabel(n.name, dark);
        plbl.position.copy(pos[n.id]); plbl.position.x += 0.5 + plbl.scale.x / 2; plbl.position.y += 0.1;
        world.add(plbl);
      });

      var octs = [];
    } else {
      // ----- fallback: findings grouped by identity (offline demo) -----
      var groups = opts.groups || [];
      var techniques = opts.techniques || [];
      var ordered2 = [];
      groups.forEach(function (g) { g.ids.forEach(function (id) { ordered2.push(id); }); });
      var pos = {};
      ordered2.forEach(function (id, i) {
        var f = (i / Math.max(1, ordered2.length - 1)) - 0.5;
        pos[id] = new THREE.Vector3(COL.mid, -f * SPAN, Math.sin(i * 1.7) * 1.4);
      });
      function meanY(ids) {
        var ys = ids.map(function (id) { return pos[id] ? pos[id].y : 0; });
        return ys.reduce(function (a, b) { return a + b; }, 0) / Math.max(1, ys.length);
      }
      var identPos = {};
      groups.forEach(function (g, gi) { identPos[g.name] = new THREE.Vector3(COL.ident, meanY(g.ids), (gi % 2 ? 1 : -1) * 0.8); });
      if (showIdent) {
        groups.forEach(function (g) {
          var box = new THREE.Mesh(new THREE.BoxGeometry(2.6, 0.8, 0.5), metal(dark ? 0x2f3437 : 0xcfd2d1, { roughness: 0.45 }));
          box.position.copy(identPos[g.name]); world.add(box);
          var edges = new THREE.LineSegments(new THREE.EdgesGeometry(box.geometry), new THREE.LineBasicMaterial({ color: dark ? 0xc3c7c6 : 0x4e5356 }));
          edges.position.copy(box.position); world.add(edges);
          g.ids.forEach(function (id) {
            var fnd = findings.find(function (x) { return x.id === id; });
            if (fnd) world.add(curveLine(identPos[g.name], pos[id], new THREE.LineBasicMaterial({ color: sev[fnd.severity], transparent: true, opacity: 0.6 })));
          });
        });
      }
      findings.forEach(function (f) {
        if (!pos[f.id]) return;
        var r = f.severity === 'CRITICAL' ? 0.34 : f.severity === 'HIGH' ? 0.29 : 0.25;
        var node = new THREE.Mesh(new THREE.SphereGeometry(r, 22, 22),
          metal(sev[f.severity], { roughness: 0.3, emissive: sev[f.severity], emissiveIntensity: dark ? 0.22 : 0.05 }));
        node.position.copy(pos[f.id]); node.userData.id = f.id; node.userData.label = f.title;
        world.add(node); picks.push(node);
      });
      var octs = [];
    }

    var HOME = { theta: -0.42, phi: 1.32, dist: 21 };
    var cam = { theta: HOME.theta, phi: HOME.phi, dist: HOME.dist };
    function applyCam() {
      camera.position.set(
        cam.dist * Math.sin(cam.phi) * Math.sin(cam.theta),
        cam.dist * Math.cos(cam.phi),
        cam.dist * Math.sin(cam.phi) * Math.cos(cam.theta));
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
    function onWheel(e) { e.preventDefault(); cam.dist = Math.max(9, Math.min(42, cam.dist + e.deltaY * 0.02)); applyCam(); }
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
