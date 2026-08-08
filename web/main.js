// Client-side proving demo.
//
// All timing lives here rather than in Rust: `std::time::Instant` panics on
// wasm32-unknown-unknown, so `performance.now()` around the calls is the only honest
// source. Every number the page displays was measured in this tab, on this machine.

import init, { PqEddsa, derive_pk_hex, achieved_security_bits, is_wide_build }
  from './pkg/pq_eddsa_wasm.js';

const $ = (id) => document.getElementById(id);
const ms = (t) => Math.round((performance.now() - t) * 10) / 10;

const status = $('status');
const setStatus = (text, cls) => {
  status.textContent = text;
  status.className = cls || '';
};

// One session per relation. Setup is the expensive part and is worth keeping.
const sessions = new Map();
let last = null; // { proof, relation }

const hexOf = (input, bytes, what) => {
  const s = input.value.trim().replace(/^0x/, '');
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error(`${what} is not hex`);
  if (s.length !== bytes * 2) {
    throw new Error(`${what} must be ${bytes * 2} hex characters, got ${s.length}`);
  }
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
};

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

$('gen').onclick = () => {
  // crypto.getRandomValues, not Math.random: this is a key, even a throwaway one.
  $('seed').value = toHex(crypto.getRandomValues(new Uint8Array(32)));
  previewPk();
};

// Show the public key as soon as a seed is present — it makes the split between secret
// and statement concrete before anyone waits two seconds for a proof.
const previewPk = () => {
  try {
    const pk = derive_pk_hex(hexOf($('seed'), 32, 'seed'));
    setStatus(`pk = ${pk}`);
  } catch {
    /* half-typed seed; say nothing */
  }
};
// A displayed statement belongs to the seed it was proved from. Once the inputs change it
// no longer describes what is in the boxes above, and on a page about the split between
// secret and statement that is exactly the confusion worth avoiding.
const markStale = () => {
  if (last) $('stale').hidden = false;
};
$('seed').addEventListener('input', () => {
  previewPk();
  markStale();
});
$('msg').addEventListener('input', markStale);
$('relation').addEventListener('change', markStale);

const row = (label, value) => `<tr><th>${label}</th><td class="n">${value}</td></tr>`;

$('prove').onclick = async () => {
  let seed, msg;
  try {
    seed = hexOf($('seed'), 32, 'seed');
    msg = hexOf($('msg'), 32, 'msg');
  } catch (e) {
    setStatus(e.message, 'bad');
    return;
  }
  const relation = $('relation').value;

  for (const b of ['prove', 'verify', 'tamper', 'download']) $(b).disabled = true;
  const timings = [];

  try {
    let session = sessions.get(relation);
    if (!session) {
      setStatus(`Building the circuit and setting up the prover (${relation})… the tab will freeze.`);
      await paint();
      const t = performance.now();
      session = new PqEddsa(relation, 1);
      timings.push(['circuit build + prover setup (one-time)', `${ms(t)} ms`]);
      sessions.set(relation, session);
      $('shape').textContent =
        `Circuit: ${session.and_constraints.toLocaleString()} AND + ` +
        `${session.imul_constraints.toLocaleString()} IMUL constraints, ` +
        `${session.private_wires.toLocaleString()} private wires, ` +
        `${session.security_bits}-bit classical soundness.`;
    }

    setStatus('Proving… the tab will freeze for a couple of seconds.');
    await paint();
    const t1 = performance.now();
    const proof = session.prove(seed, msg);
    timings.push(['prove', `${ms(t1)} ms`]);

    const bytes = proof.bytes;
    const t2 = performance.now();
    session.verify(bytes, proof.pk, proof.msg, proof.hx);
    timings.push(['verify', `${ms(t2)} ms`]);
    timings.push(['proof size', `${(bytes.length / 1024).toFixed(1)} KiB`]);

    $('out-pk').textContent = proof.pk;
    $('out-msg').textContent = proof.msg;
    $('out-hx').textContent = proof.hx;
    $('timings').innerHTML = timings.map(([k, v]) => row(k, v)).join('');
    $('results').hidden = false;
    $('stale').hidden = true;

    // Release the previous proof only once the new one is safely installed. wasm-bindgen
    // registers a FinalizationRegistry, so this is about releasing half a megabyte
    // promptly rather than at the GC's convenience — but freeing before the swap would
    // leave `last` dangling if anything above threw, and the next free() would then
    // throw "null pointer passed to rust" over a proof that had actually succeeded.
    const prev = last;
    last = { proof, bytes, relation };
    if (prev) prev.proof.free();

    setStatus('Proof generated and verified, here in this tab.', 'ok');
    for (const b of ['verify', 'tamper', 'download']) $(b).disabled = false;
  } catch (e) {
    setStatus(String(e && e.message ? e.message : e), 'bad');
  } finally {
    $('prove').disabled = false;
  }
};

$('verify').onclick = async () => {
  const { proof, bytes, relation } = last;
  await paint();
  const t = performance.now();
  try {
    sessions.get(relation).verify(bytes, proof.pk, proof.msg, proof.hx);
    setStatus(`Verified in ${ms(t)} ms.`, 'ok');
  } catch (e) {
    setStatus(`Unexpected: ${e.message}`, 'bad');
  }
};

// The honest half of the demo. A proof is valid for whatever statement accompanies it,
// so the interesting question is not "does it verify" but "does it stop verifying when
// the statement changes". Flip one bit of pk and watch it fail.
$('tamper').onclick = async () => {
  const { proof, bytes, relation } = last;
  const flipped = (proof.pk.slice(0, 1) === '0' ? '1' : '0') + proof.pk.slice(1);
  await paint();
  try {
    sessions.get(relation).verify(bytes, flipped, proof.msg, proof.hx);
    setStatus('Tampered statement was ACCEPTED — that is a bug, please report it.', 'bad');
  } catch {
    setStatus(`Rejected, as it must be: the proof does not verify against pk ${flipped.slice(0, 16)}…`, 'ok');
  }
};

$('download').onclick = () => {
  const blob = new Blob([last.bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  // Build in the name, not just in the status line below. The same seed and relation
  // produce the same filename from a narrow page and a wide one, so the two land in
  // Downloads as `x.proof` and `x (1).proof` — indistinguishable, needing different CLIs.
  // The status line is gone by then; the filename is what survives.
  a.download =
    `pq-eddsa-${is_wide_build() ? 'wide' : 'narrow'}-${last.relation}` +
    `-${last.proof.pk.slice(0, 8)}.proof`;
  // Appended, and revoked on a later turn: revoking synchronously after click() can
  // cancel the download before it starts, and a detached anchor does not always fire.
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
  // The CLI has to be built the way this page was. The field, hash suite and challenger
  // are chosen at compile time, so a default narrow CLI cannot read a wide proof — and it
  // fails the way a forged proof does, which is the confusion worth spending a flag on.
  setStatus(
    'Downloaded. Check it against the native verifier: ' +
      `cargo run --release --bin cli${is_wide_build() ? ' --features wide' : ''} -- ` +
      'verify --proof <file> --pk <pk> --msg <msg> --hx <hx>' +
      (last.relation === 'rand' ? ' --relation rand' : ''),
    'ok',
  );
};

/// Let the browser render the status line before a call that blocks the main thread.
const paint = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));

await init();

// Asked, not asserted. The level and the logUp* cap it is clamped to both live in
// config.rs, where the field is known; a number written here would be a third copy. This
// page, the CLI help and the stat subcommand each hardcoded one once.
const achieved = achieved_security_bits();
const quantum = Math.round(achieved / 2); // square-root Grover on Fiat-Shamir search
$('soundness').textContent = is_wide_build()
  ? `~${achieved}-bit classical and ~${quantum}-bit quantum soundness, from an unmerged, `
    + 'unaudited fork of Binius64'
  : `${achieved}-bit classical and ~${quantum}-bit quantum soundness, the ceiling upstream `
    + 'Binius64 exposes and below the ~128 you should want in production';

$('seed').value = toHex(crypto.getRandomValues(new Uint8Array(32)));
previewPk();
$('prove').disabled = false;
