// Browser-side trust-verification driver.
//
// The page's exact <script> from kc/transparency.html is prepended by the
// python harness; PAY holds a deterministic large multi-purpose tree.
(async () => {
  const r = {};
  const lh = await Promise.all(PAY.leaves.map(leafHash));
  const cur = PAY.heads[PAY.heads.length - 1];
  const total = cur.tree_size;

  // --- crypto vectors (guards the pure-JS SHA-512/Ed25519) ---------------
  r.sha512_empty =
    hex(Sha512.hash(asciiBytes(""))) ===
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
  r.sha512_abc =
    hex(Sha512.hash(asciiBytes("abc"))) ===
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
  r.ed25519_rfc1 = Ed.verify(
    unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    new Uint8Array(0),
    unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555" +
          "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));
  r.ed25519_rfc2 = Ed.verify(
    unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    Uint8Array.from([0x72]),
    unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
          "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"));

  // --- current head --------------------------------------------------------
  const prev = total >= 2 ? PAY.heads[total - 2] : null;
  r.currentTrusted =
    (await evaluateHead(cur, total, lh, prev, PAY.pub)).trusted;

  // --- every historical head + chain links --------------------------------
  const badSizes = [];
  for (let s = 1; s <= total; s++) {
    const ev = await evaluateHead(
      PAY.heads[s - 1], s, lh, s >= 2 ? PAY.heads[s - 2] : null, PAY.pub);
    if (!ev.trusted) badSizes.push(s);
  }
  r.everyHistoryTrusted = badSizes.length === 0;
  r.historyBadSizes = badSizes;

  let chainOk = PAY.heads[0].prev_head_hash === "0".repeat(64);
  for (let s = 1; s < total; s++) {
    if (PAY.heads[s].prev_head_hash !== await headHashOf(PAY.heads[s - 1]))
      chainOk = false;
  }
  r.headChainLinked = chainOk;

  // --- member (inclusion) path rebuilt entirely in-browser ----------------
  function hp(n) { return 1 << (31 - Math.clz32(n - 1)); }
  async function incPath(index, size, hs, st, out) {
    if (size === 1) return;
    const k = hp(size);
    if (index < k) {
      await incPath(index, k, hs, st, out);
      out.push(hex(await subtreeRange(hs, st + k, size - k)));
    } else {
      out.push(hex(await mth(hs, st, k)));
      await incPath(index - k, size - k, hs, st + k, out);
    }
  }
  const idx = 3;
  const path = [];
  await incPath(idx, total, lh, 0, path);
  r.memberPathRebuilt =
    await verifyInclusion(idx, total, path, lh[idx], unhex(cur.root_hash));

  // --- tamper: summary content / attestation field -> untrusted ------------
  const t1 = JSON.parse(JSON.stringify(cur));
  t1.root_hash = "ab".repeat(32);
  r.changedRootUntrusted =
    (await evaluateHead(t1, total, lh, prev, PAY.pub)).trusted === false;

  const t2 = JSON.parse(JSON.stringify(cur));
  const sb = Buffer.from(t2.tree_head_sig, "base64");
  sb[3] ^= 1;
  t2.tree_head_sig = sb.toString("base64");
  r.changedSigUntrusted =
    (await evaluateHead(t2, total, lh, prev, PAY.pub)).trusted === false;

  const evilLeaf = JSON.parse(JSON.stringify(PAY.leaves[1]));
  evilLeaf.fingerprint = "TAMPERED";
  const t3hashes = lh.slice();
  t3hashes[1] = await leafHash(evilLeaf);
  r.changedLeafContentUntrusted =
    (await evaluateHead(cur, total, t3hashes, prev, PAY.pub)).trusted === false;

  // a valid head signed by a DIFFERENT key must be untrusted
  if (PAY.foreign_signed_head) {
    r.foreignKeyHeadUntrusted = (await evaluateHead(
      PAY.foreign_signed_head, total, lh, prev, PAY.pub)).trusted === false;
  }

  // same-height divergence: a correctly-signed head whose root the local
  // leaves do not produce must still be untrusted (the page never trusts a
  // signature alone; it binds the root to independently recomputed leaves).
  if (PAY.equivocal_head) {
    const eqEv = await evaluateHead(
      PAY.equivocal_head, total, lh, prev, PAY.pub);
    r.equivocalSigValid = verifyHeadSig(PAY.pub, PAY.equivocal_head);
    r.equivocalHeadUntrusted = eqEv.trusted === false;
  }

  // --- reproducibility: same inputs => same verdict -----------------------
  const a = await evaluateHead(cur, total, lh, prev, PAY.pub);
  const b = await evaluateHead(JSON.parse(JSON.stringify(cur)), total,
                               lh.map(h => h.slice ? unhex(hex(h)) : h),
                               prev, PAY.pub);
  r.reproducible = a.trusted === b.trusted && a.trusted === true;

  // --- strict-append: legal extension accepted, attacks rejected ----------
  const m = Math.min(20, total - 1);
  const oldRoot = unhex(PAY.heads[m - 1].root_hash);
  r.legalExtensionPasses = await verifyConsistency(
    m, total, await consistencyProofLocal(m, total, lh),
    oldRoot, unhex(cur.root_hash));

  // 1. tail truncation: claims the CURRENT root over a shorter leaf set
  const tr = lh.slice(0, total - 10);
  const trProof = await consistencyProofLocal(m, tr.length, tr);
  r.tailTruncationFails = (await verifyConsistency(
    m, total, trProof, oldRoot, unhex(cur.root_hash))) === false;

  // an honest shorter prefix genuinely extends (no false positive)
  r.honestPrefixPasses = await verifyConsistency(
    m, tr.length, trProof, oldRoot, await rootOf(tr));

  // 2. leaf reorder
  const ro = lh.slice();
  [ro[0], ro[5]] = [ro[5], ro[0]];
  r.reorderFails = (await verifyConsistency(
    m, total, await consistencyProofLocal(m, total, ro),
    oldRoot, await rootOf(ro))) === false;

  // 3. early entry rewritten
  const erLeaf = JSON.parse(JSON.stringify(PAY.leaves[2]));
  erLeaf.fingerprint = "EVIL";
  const er = lh.slice();
  er[2] = await leafHash(erLeaf);
  r.earlyRewriteFails = (await verifyConsistency(
    m, total, await consistencyProofLocal(m, total, er),
    oldRoot, await rootOf(er))) === false;

  // 4. splice another tree's leaves
  const fo = await Promise.all(Array.from(
    {length: total}, (_, i) => leafHash({
      purpose: "other-tree", version: i + 700, version_id: "x",
      fingerprint: "f", signing_pub: "Q", event: "STAGED",
      state: {prev: "NONE", next: "STAGED"},
      ceremony_id: "z", audit_ref: "foreign" + i})));
  r.foreignTreeFails = (await verifyConsistency(
    m, total, await consistencyProofLocal(m, total, fo),
    oldRoot, await rootOf(fo))) === false;

  console.log(JSON.stringify(r));
})();
