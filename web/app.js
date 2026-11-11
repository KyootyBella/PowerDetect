"use strict";
/* PowerDetect web front-end.
 * The analysis engine is the Python package itself, running in Pyodide (WebAssembly).
 * SECURITY: everything shown comes from potentially hostile command lines, so all
 * report data is inserted with esc() / textContent - never as raw HTML. */

// Bundled runtime (tools/fetch_pyodide.py), served from this site - no CDN, works offline.
const PYODIDE_URL = new URL("pyodide/", location.href).href;
const RANK = { LOW: 0, SUSPICIOUS: 1, MALICIOUS: 2 };
// Example commands, base64-encoded so the shipped file holds no plain attack strings.
const EXAMPLES = [
	"Y21kLmV4ZSAvYyBwXm93ZXJec2hlbGwgLXcgaF5pZGRlbiAtYyAidnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQi",
	"R2V0LUNsaXBib2FyZCB8IGlleA==",
	"R2V0LVNlcnZpY2UgfCBXaGVyZS1PYmplY3QgU3RhdHVzIC1lcSBSdW5uaW5n",
];
const BIG_INPUT = 400000; // characters; larger inputs are kept out of the textarea
const AUTO_OPEN = 12; // open the details of the first N flagged rows

const $ = (id) => document.getElementById(id);
let api = null,
	info = null,
	last = null,
	loadedText = null;

function esc(s) {
	return String(s ?? "").replace(
		/[&<>"']/g,
		(c) =>
			({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
	);
}
function oneLine(s, n) {
	s = String(s ?? "")
		.replace(/\s+/g, " ")
		.trim();
	return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function setStatus(msg, err = false) {
	const el = $("status");
	el.textContent = msg;
	el.classList.toggle("err", err);
}
function where(s) {
	return s.layer === null ? "host" : `L${s.layer}#${s.index}`;
}
function tacticName(t) {
	return (info && info.tactics[t]) || t;
}
function tacticOrder(t) {
	const i = info ? Object.keys(info.tactics).indexOf(t) : -1;
	return i < 0 ? 99 : i;
}
function techLinks(m) {
	if (!m) return "";
	return m
		.split(/\s*,\s*/)
		.filter(Boolean)
		.map((t) =>
			/^T\d{4}(\.\d{3})?$/.test(t)
				? `<a href="https://attack.mitre.org/techniques/${t.replace(".", "/")}/" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`
				: esc(t),
		)
		.join(" ");
}
function pyError(e) {
	const lines = String((e && e.message) || e)
		.trim()
		.split("\n");
	return lines[lines.length - 1];
}
function download(name, text, type) {
	const url = URL.createObjectURL(new Blob([text], { type }));
	const a = document.createElement("a");
	a.href = url;
	a.download = name;
	document.body.appendChild(a);
	a.click();
	a.remove();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ------------------------------------------------------------------ boot
async function boot() {
	try {
		setStatus(
			"Loading the bundled Python runtime. The first load is about 13 MB; after that it is cached.",
		);
		const py = await loadPyodide({ indexURL: PYODIDE_URL });
		const manifest = await (
			await fetch("py/manifest.json", { cache: "no-cache" })
		).json();
		py.FS.mkdirTree("/pd/powerdetect");
		await Promise.all(
			manifest.files.map(async (f) => {
				const r = await fetch("py/" + f, { cache: "no-cache" });
				if (!r.ok) throw new Error(`could not load ${f} (${r.status})`);
				py.FS.writeFile("/pd/" + f, new Uint8Array(await r.arrayBuffer()));
			}),
		);
		py.runPython("import sys; sys.path.insert(0, '/pd')");
		api = py.pyimport("powerdetect.webapi");
		info = JSON.parse(api.init(manifest.db ? "/pd/" + manifest.db : null));
		if (info.db) {
			$("dbcount").textContent = `(${info.db.toLocaleString()})`;
		} else {
			$("usedb").checked = false;
			$("usedb").disabled = true;
			$("dbcount").textContent = "(not in this build)";
		}
		const meta = $("meta");
		meta.textContent = `${info.rules} rules · ${info.combos} combos · build ${manifest.version.slice(0, 8)} · offline`;
		meta.classList.add("ok");
		$("run").disabled = false;
		setStatus("Ready.");
	} catch (e) {
		$("meta").textContent = "engine failed to load";
		setStatus(
			"The engine could not load: " +
				pyError(e) +
				(location.protocol === "file:"
					? ". Open the page through a web server; file:// does not work."
					: ""),
			true,
		);
	}
}

// ------------------------------------------------------------------ input
function currentKind() {
	return document.querySelector('input[name="kind"]:checked').value;
}
function setKind(k) {
	const el = document.querySelector(`input[name="kind"][value="${k}"]`);
	if (el) el.checked = true;
}

async function loadFile(file) {
	const text = await file.text();
	const ext = (file.name.split(".").pop() || "").toLowerCase();
	setKind(
		ext === "csv"
			? "csv"
			: ext === "json"
				? "json"
				: ext === "ps1"
					? "whole"
					: "lines",
	);
	const ta = $("input");
	if (text.length > BIG_INPUT) {
		loadedText = text;
		ta.value = "";
		ta.placeholder = `${file.name} is loaded (${(text.length / 1048576).toFixed(1)} MB, too large to display). Type here to analyze something else instead.`;
	} else {
		loadedText = null;
		ta.value = text;
	}
	setStatus(`Loaded ${file.name}.`);
}

async function analyze() {
	if (!api) return;
	const typed = $("input").value;
	const text = typed.trim() ? typed : loadedText || "";
	if (!text.trim()) {
		setStatus("Nothing to analyze. Paste commands or open a file.", true);
		return;
	}
	const btn = $("run");
	btn.disabled = true;
	btn.textContent = "Working";
	setStatus("Analyzing…");
	await new Promise((r) => setTimeout(r, 30)); // let the UI repaint
	const t0 = performance.now();
	try {
		last = JSON.parse(api.run(text, currentKind(), $("usedb").checked));
		last.reports.forEach((r, i) => {
			r.index = i + 1;
		});
		last.ms = Math.round(performance.now() - t0);
		render();
		setStatus(
			last.truncated
				? `${last.truncated} commands over the limit were skipped.`
				: "",
		);
	} catch (e) {
		setStatus("Analysis failed: " + pyError(e), true);
	} finally {
		btn.disabled = false;
		btn.textContent = "Analyze";
	}
}

function render() {
	if (!last) return;
	$("results").hidden = false;
	const c = last.counts;
	$("counts").innerHTML =
		["MALICIOUS", "SUSPICIOUS", "LOW"]
			.map(
				(v) =>
					`<div class="stat ${v}"><b>${c[v].toLocaleString()}</b><span>${v.toLowerCase()}</span></div>`,
			)
			.join("") +
		`<div class="stat"><b>${last.distinct.toLocaleString()}</b><span>distinct fingerprints</span></div>`;
	$("runinfo").textContent =
		`${last.reports.length.toLocaleString()} commands · ${last.ms} ms` +
		($("usedb").checked && info.db ? " · fingerprint DB on" : "");

	renderClusters();
	const hide = $("onlyflagged").checked;
	const reps = last.reports
		.filter((r) => !hide || r.verdict !== "LOW")
		.sort(
			(a, b) =>
				RANK[b.verdict] - RANK[a.verdict] || b.score - a.score || a.index - b.index,
		);
	let opened = 0;
	$("cards").innerHTML = reps.length
		? reps
				.map((r) =>
					row(r, r.verdict !== "LOW" && opened++ < AUTO_OPEN && reps.length <= 40),
				)
				.join("")
		: `<div class="empty">Nothing to show${hide ? " (LOW results are hidden)" : ""}.</div>`;
}

function renderClusters() {
	const cl = last.clusters.filter((k) => k.count > 1); // a cluster of one is not a cluster
	if (!cl.length) {
		$("clusters").innerHTML = "";
		return;
	}
	$("clusters").innerHTML = `<section class="clusters">
    <div class="label">Clusters: same structure after deobfuscation</div>
    <div class="tablewrap panel"><table>
      <thead><tr><th>fingerprint</th><th>n</th><th>verdict</th><th>rows</th><th>skeleton</th></tr></thead>
      <tbody>${cl
							.map(
								(k) => `<tr>
        <td class="mono">${esc(k.fingerprint)}${k.label ? `<div class="dim">${esc(oneLine(k.label, 70))}</div>` : ""}</td>
        <td class="mono">${k.count}</td>
        <td><span class="v ${k.verdict}">${k.verdict}</span></td>
        <td class="mono">${k.members
									.slice(0, 20)
									.map((i) => `<a href="#cmd-${i}" data-open="${i}">${i}</a>`)
									.join(" ")}${k.members.length > 20 ? " …" : ""}</td>
        <td class="mono">${esc(oneLine(k.skeleton, 150))}</td></tr>`,
							)
							.join("")}
      </tbody></table></div></section>`;
}

function hit(h, stmtText) {
	const crit = h.min_verdict
		? `<span class="crit">forces ≥ ${esc(h.min_verdict)}</span>`
		: "";
	let ev = "";
	if (h.statements && h.statements.length) {
		const w = h.statements[0];
		const more = h.statements.length > 1 ? ` +${h.statements.length - 1}` : "";
		ev = `<div class="ev"><span class="loc">${esc(w)}${more}</span><code>${esc(oneLine(stmtText[w] || h.evidence, 240))}</code></div>`;
	} else if (h.evidence) {
		ev = `<div class="ev"><span class="loc">${h.kind === "combo" ? "from" : h.kind === "killchain" ? "tactics" : "note"}</span><code>${esc(oneLine(h.evidence, 240))}</code></div>`;
	}
	return `<div class="hit"><span class="w">+${h.weight}</span><div>
    <div class="h"><b>${esc(h.name)}</b><span class="rid">${esc(h.id)}</span><span class="tech">${techLinks(h.mitre)}</span>${crit}</div>
    <p class="why">${esc(h.why)}</p>${ev}</div></div>`;
}

function row(r, open) {
	const stmtText = {};
	r.statements.forEach((s) => {
		stmtText[where(s)] = s.text;
	});
	const signals = r.hits.filter(
		(h) => h.kind === "rule" || h.kind === "obfuscation",
	);
	const logic = r.hits.filter(
		(h) => h.kind === "combo" || h.kind === "killchain",
	);
	const topNames = r.hits.slice(0, 2).map((h) => h.name);
	if (r.known.length) topNames.unshift("known pattern");

	const groups = {};
	signals
		.slice()
		.sort(
			(a, b) =>
				tacticOrder(a.tactic) - tacticOrder(b.tactic) || b.weight - a.weight,
		)
		.forEach((h) => {
			(groups[h.tactic] = groups[h.tactic] || []).push(h);
		});
	const reasons = Object.entries(groups)
		.map(
			([t, hs]) =>
				`<div class="tac">${esc(tacticName(t))}</div>${hs.map((h) => hit(h, stmtText)).join("")}`,
		)
		.join("");

	const fps = r.hits.filter((h) => h.fp);
	const iocs = Object.entries(r.iocs).filter(([, v]) => v.length);
	const f = r.fingerprints;
	const flagged = r.statements.filter((s) => s.rules.length).length;

	return `<details class="card ${r.verdict}" id="cmd-${r.index}"${open ? " open" : ""}>
  <summary>
    <span class="v ${r.verdict}">${r.verdict}</span>
    <span class="score">${r.score}<small>pts</small></span>
    <span class="top">${esc(topNames.join(" · ") || "no indicators")}</span>
    <span class="n">#${r.index}</span>
    <code class="cmd" title="${esc(oneLine(r.raw, 2000))}">${esc(oneLine(r.raw, 400))}</code>
  </summary>
  <div class="detail">
    <div class="main">
      <p class="lead"><b>${r.verdict}</b>: ${esc(r.verdict_reason)}${r.verdict_source !== "score" ? " (fingerprint DB match)" : ""}.</p>
      <p class="prose">${esc(r.assessment)}</p>
      ${reasons ? `<div class="label">Reasons</div>${reasons}` : ""}
      ${logic.length ? `<div class="label">Combined evidence</div>${logic.map((h) => hit(h, stmtText)).join("")}` : ""}
      <details class="more"><summary>statements (${r.statements.length}, ${flagged} flagged)</summary>
        <div class="stmts">${r.statements
									.map(
										(s) =>
											`<div${s.rules.length ? ' class="hl"' : ""}><span class="at">${esc(where(s))}</span>${esc(s.text)}${s.rules.length ? ` <span class="ids">← ${esc(s.rules.join(", "))}</span>` : ""}</div>`,
									)
									.join("")}</div>
      </details>
      <details class="more"><summary>deobfuscated code (${r.layers.length} layer${r.layers.length === 1 ? "" : "s"})</summary>
        ${r.layers.map((l, i) => `<div class="layer">L${i} · ${esc(l.source)}</div><pre>${esc(l.text)}</pre>`).join("")}
        <div class="layer">skeleton (input to the structural fingerprint)</div><pre>${esc(r.skeleton)}</pre>
      </details>
      <details class="more"><summary>original command</summary><pre>${esc(r.raw)}</pre></details>
    </div>
    <aside class="side">
      ${
							r.known.length
								? `<h4>Known pattern</h4>${r.known
										.map(
											(k) =>
												`<p class="known">${esc(k.label)} <span class="dim">(${esc(k.type)}${k.verdict ? ", " + esc(k.verdict) : ", context only"})</span></p>`,
										)
										.join("")}`
								: ""
						}
      ${
							fps.length && r.verdict !== "LOW"
								? `<h4>Check before escalating</h4><ul class="notes">${fps
										.map((h) => `<li><b>${esc(h.id)}</b> ${esc(h.fp)}</li>`)
										.join("")}</ul>`
								: ""
						}
      ${
							iocs.length
								? `<h4>IOCs</h4><dl class="kv">${iocs
										.map(
											([k, v]) => `<dt>${esc(k)}</dt><dd>${v.map(esc).join("<br>")}</dd>`,
										)
										.join("")}</dl>`
								: ""
						}
      <h4>Fingerprints</h4>
      <dl class="kv">
        <dt>structural</dt><dd>${esc(f.structural)}</dd><dt>payload</dt><dd>${esc(f.payload)}</dd>
        <dt>behavior</dt><dd>${esc(f.behavior)}</dd><dt>exact</dt><dd>${esc(f.exact)}</dd>
        <dt>sha256</dt><dd>${esc(r.sha256)}</dd>
      </dl>
    </aside>
  </div>
</details>`;
}

// ------------------------------------------------------------------ wiring
function wire() {
	$("run").addEventListener("click", analyze);
	$("input").addEventListener("keydown", (e) => {
		if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
			e.preventDefault();
			analyze();
		}
	});
	$("input").addEventListener("input", () => {
		if (loadedText) {
			loadedText = null;
			$("input").placeholder =
				"Paste ProcessCommandLine values, one per line, or drop a CSV / JSON export here.";
		}
	});
	$("file").addEventListener("change", (e) => {
		const f = e.target.files[0];
		if (f) loadFile(f);
		e.target.value = "";
	});
	const ta = $("input");
	ta.addEventListener("dragover", (e) => {
		e.preventDefault();
		ta.classList.add("drag");
	});
	ta.addEventListener("dragleave", () => ta.classList.remove("drag"));
	ta.addEventListener("drop", (e) => {
		e.preventDefault();
		ta.classList.remove("drag");
		const f = e.dataTransfer.files[0];
		if (f) loadFile(f);
	});
	$("example").addEventListener("click", () => {
		const dec = new TextDecoder();
		$("input").value = EXAMPLES.map((b) =>
			dec.decode(Uint8Array.from(atob(b), (ch) => ch.charCodeAt(0))),
		).join("\n");
		loadedText = null;
		setKind("lines");
		setStatus(
			`Loaded ${EXAMPLES.length} examples: one malicious, one suspicious, one benign.`,
		);
	});
	$("onlyflagged").addEventListener("change", render);
	$("clusters").addEventListener("click", (e) => {
		const a = e.target.closest("a[data-open]");
		if (a) {
			const d = $("cmd-" + a.dataset.open);
			if (d) d.open = true;
		}
	});
	$("exp-json").addEventListener("click", () => {
		if (last)
			download(
				"powerdetect-results.json",
				JSON.stringify(last, null, 2),
				"application/json",
			);
	});
	$("exp-fp").addEventListener("click", () => {
		if (api && last)
			download(
				"powerdetect-fingerprints.toml",
				api.export_fingerprints(),
				"application/toml",
			);
	});
}

wire();
boot();
