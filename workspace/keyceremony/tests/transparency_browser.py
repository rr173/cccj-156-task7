#!/usr/bin/env python3
"""Browser-side trust-verification coverage for the transparency page.

The exact JavaScript embedded in ``kc/transparency.html`` is concatenated
with ``transparency_browser_driver.js`` and evaluated under node against a
deterministic, large multi-purpose tree built purely from public leaf data.
These assertions exercise the *page's* verdict functions (evaluateHead,
verifyInclusion, consistencyProofLocal + verifyConsistency, Ed/Sha512), so a
frontend trust regression fails here even when the server is correct:

  * as-served current head -> TRUSTED at any scale,
  * every historical head and the prev_head_hash chain verify,
  * member (inclusion) path rebuilt in-browser,  * changed root / signature / leaf content / foreign key -> UNTRUSTED,
  * same inputs always give the same verdict (reproducible),
  * legal strict-append passes; tail truncation, reorder, early-entry rewrite
    and foreign-tree splicing fail (an honest shorter prefix still passes).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from kc import crypto, ed25519  # noqa: E402
from kc.transparency import (  # noqa: E402
    TransparencyLog, head_content, sign_head,
    make_leaf, CREATED, STAGED, NONE_STATE,
)

HTML = os.path.join(ROOT, "kc", "transparency.html")
DRIVER = os.path.join(HERE, "transparency_browser_driver.js")

NODE_STUB = """
const __store = {};
const localStorage = {
  getItem: k => (k in __store ? __store[k] : null),
  setItem: (k, v) => { __store[k] = String(v); },
  removeItem: k => { delete __store[k]; }
};
const __els = {};
const document = {
  getElementById: id => __els[id] ||
    (__els[id] = {innerHTML: "", textContent: "", value: "",
                  disabled: false, style: {}}),
  addEventListener: () => {}
};
const fetch = async () => ({ json: async () => ({}) });
"""

EXPECTED_TRUE = [
    "sha512_empty", "sha512_abc", "ed25519_rfc1", "ed25519_rfc2",
    "currentTrusted", "everyHistoryTrusted", "headChainLinked",
    "memberPathRebuilt", "changedRootUntrusted", "changedSigUntrusted",
    "changedLeafContentUntrusted", "foreignKeyHeadUntrusted",
    "equivocalSigValid", "equivocalHeadUntrusted",
    "reproducible",
    "legalExtensionPasses", "tailTruncationFails", "honestPrefixPasses",
    "reorderFails", "earlyRewriteFails", "foreignTreeFails",
]


def page_javascript():
    html = open(HTML, encoding="utf-8").read()
    js = re.search(r"<script>(.*)</script>", html, re.S).group(1)
    return js.replace("\nif (HAS_DOM) refresh();", "")


def build_tree(directory, n=64, purposes=9):
    seed = bytes(range(32))
    log = TransparencyLog(directory, service_seed=seed)
    with log.locked() as l:
        for i in range(n):
            purpose = "root-signing" if i == 0 else f"svc-{i % purposes}"
            l.record(make_leaf(
                purpose, i + 1, f"vid-{i}", f"fp-{i % 5}", f"PUB{i % 9}",
                CREATED if i == 0 else STAGED, NONE_STATE,
                f"cer-{i % 4}", f"audit-{i}"))
        cur = l.current_head()
        # a structurally valid head signed by a DIFFERENT log key
        foreign_seed = bytes([7]) * 32
        foreign = head_content(cur["tree_size"], cur["root_hash"],
                               cur["issued_at"], cur["prev_head_hash"])
        foreign["tree_head_sig"] = sign_head(foreign_seed, foreign)
        # same-height divergence: the real key signs a head with a foreign
        # root at the same tree size (an equivocating control instance)
        equivocal = head_content(cur["tree_size"], "ee" * 32,
                                 cur["issued_at"], cur["prev_head_hash"])
        equivocal["tree_head_sig"] = sign_head(seed, equivocal)
        payload = {
            "leaves": l._committed_leaves(),
            "heads": l.cp["heads"],
            "pub": crypto.b64e(ed25519.public_from_secret(seed)),
            "foreign_signed_head": foreign,
            "equivocal_head": equivocal,
        }
    return payload


def run_node(payload):
    node = shutil.which("node")
    if not node:
        print("node unavailable; skipping browser-side page tests")
        return None
    driver = open(DRIVER, encoding="utf-8").read()
    full = NODE_STUB + page_javascript() + \
        "\nconst PAY = " + json.dumps(payload) + ";\n" + driver
    r = subprocess.run([node, "-e", full], capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError("node driver failed:\n" + r.stderr[-3000:])
    return json.loads(r.stdout.strip().splitlines()[-1])


def main():
    tmp = tempfile.mkdtemp(prefix="kc-browser-")
    try:
        results = run_node(build_tree(tmp))
        if results is None:
            return 0
        failed = []
        for k in EXPECTED_TRUE:
            ok = results.get(k) is True
            print(f"  [{'PASS' if ok else 'FAIL'}] {k}")
            if not ok:
                failed.append(k)
        if results.get("historyBadSizes"):
            print("  bad history sizes:", results["historyBadSizes"])
        if failed:
            print("BROWSER PAGE TESTS FAILED:", failed)
            print(json.dumps(results, indent=1))
            return 1
        print("BROWSER PAGE TESTS PASSED")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
