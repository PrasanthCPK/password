/* ------------------------------------------------------------------
   Strong Password Generator
   Vanilla JS, no dependencies. Generates a 14-character password with
   the Web Crypto API and validates it against a fixed set of rules.
   ------------------------------------------------------------------ */
(function () {
  "use strict";

  const PASSWORD_LENGTH = 14;

  // Character classes with ambiguous characters removed:
  //   uppercase: no O, I     lowercase: no l     digits: no 0, 1
  //   specials:  no |, backtick, or space
  const CHAR_CLASSES = {
    upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
    lower: "abcdefghijkmnopqrstuvwxyz",
    digit: "23456789",
    special: "!@#$%^&*()-_=+[]{};:,.<>?/~",
  };
  const ALL_CHARS = Object.values(CHAR_CLASSES).join("");
  const AMBIGUOUS = /[O0Il1|`]/;

  /* ---------- Secure random helpers ---------- */

  /**
   * Returns a uniformly distributed integer in [0, max).
   *
   * crypto.getRandomValues() fills a typed array with cryptographically
   * strong random bytes. A plain `byte % max` would bias the result toward
   * lower values when 256 is not a multiple of `max`, so we use rejection
   * sampling: discard any byte that falls in the "leftover" range at the
   * top and draw again. This keeps every character equally likely.
   */
  function secureRandomInt(max) {
    if (max <= 0 || max > 256) {
      throw new RangeError("max must be between 1 and 256");
    }
    const limit = 256 - (256 % max); // largest multiple of max that fits in a byte
    const buf = new Uint8Array(1);
    let value;
    do {
      crypto.getRandomValues(buf);
      value = buf[0];
    } while (value >= limit);
    return value % max;
  }

  /** Picks one random character from a string. */
  function secureRandomChar(chars) {
    return chars[secureRandomInt(chars.length)];
  }

  /** Fisher–Yates shuffle driven by the secure RNG (in place). */
  function secureShuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  /* ---------- Validation ---------- */

  /**
   * Detects three-character runs that are either identical (aaa, 111)
   * or strictly sequential in either direction (abc, cba, 123, 321).
   * Letters are compared case-insensitively so "aBc" also counts.
   */
  function hasObviousPattern(pw) {
    const codes = Array.from(pw.toLowerCase(), (c) => c.charCodeAt(0));
    for (let i = 0; i + 2 < codes.length; i++) {
      const a = codes[i];
      const b = codes[i + 1];
      const c = codes[i + 2];
      const repeated = a === b && b === c;
      const ascending = b === a + 1 && c === b + 1;
      const descending = b === a - 1 && c === b - 1;
      if (repeated || ascending || descending) {
        return true;
      }
    }
    return false;
  }

  /**
   * Runs every rule against a password and returns a map of
   * rule name -> boolean. The same map drives the on-page checklist.
   */
  function validate(pw) {
    return {
      length: pw.length === PASSWORD_LENGTH,
      upper: /[A-Z]/.test(pw),
      lower: /[a-z]/.test(pw),
      digit: /[0-9]/.test(pw),
      special: /[^A-Za-z0-9]/.test(pw),
      ambiguous: !AMBIGUOUS.test(pw),
      space: !/\s/.test(pw),
      pattern: !hasObviousPattern(pw),
    };
  }

  function passesAllRules(results) {
    return Object.values(results).every(Boolean);
  }

  /* ---------- Generation ---------- */

  /**
   * Builds one candidate password:
   *   1. Take one character from each class so every class is guaranteed.
   *   2. Fill the remaining slots from the full pool.
   *   3. Shuffle so the guaranteed characters are not always at the front.
   */
  function buildCandidate() {
    const chars = Object.values(CHAR_CLASSES).map(secureRandomChar);
    while (chars.length < PASSWORD_LENGTH) {
      chars.push(secureRandomChar(ALL_CHARS));
    }
    return secureShuffle(chars).join("");
  }

  /**
   * Generates candidates until one satisfies every rule. The pattern rule is
   * the only one a candidate can realistically fail, and it fails rarely, so
   * this loop almost always exits on the first or second attempt. The cap is
   * a safety net, not something we expect to hit.
   */
  function generatePassword() {
    const MAX_ATTEMPTS = 100;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const candidate = buildCandidate();
      if (passesAllRules(validate(candidate))) {
        return candidate;
      }
    }
    throw new Error("Could not generate a compliant password");
  }

  /* ---------- UI ---------- */

  const passwordField = document.getElementById("password");
  const generateBtn = document.getElementById("generate-btn");
  const copyBtn = document.getElementById("copy-btn");
  const copyStatus = document.getElementById("copy-status");
  const checklistItems = document.querySelectorAll("#checklist li[data-rule]");

  let statusTimer = null;

  function renderChecklist(results) {
    checklistItems.forEach((li) => {
      const ok = results[li.dataset.rule] === true;
      li.classList.toggle("is-pass", ok);
      li.classList.toggle("is-fail", !ok);
      // Expose pass/fail state to assistive tech without relying on color
      li.setAttribute("aria-label", `${li.textContent.trim()}: ${ok ? "met" : "not met"}`);
    });
  }

  function setStatus(message, isError) {
    copyStatus.textContent = message;
    copyStatus.classList.toggle("is-error", Boolean(isError));
    copyBtn.classList.toggle("is-copied", Boolean(message) && !isError);
    clearTimeout(statusTimer);
    if (message) {
      statusTimer = setTimeout(() => setStatus("", false), 2000);
    }
  }

  function showNewPassword() {
    try {
      const pw = generatePassword();
      passwordField.value = pw;
      renderChecklist(validate(pw));
      setStatus("", false);
    } catch (err) {
      passwordField.value = "";
      setStatus("Something went wrong. Please try again.", true);
    }
  }

  /**
   * Copies via the asynchronous Clipboard API. If that is unavailable
   * (older browsers, some non-secure contexts) fall back to selecting
   * the field and using the legacy execCommand path.
   */
  async function copyPassword() {
    const pw = passwordField.value;
    if (!pw) {
      setStatus("Nothing to copy yet.", true);
      return;
    }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(pw);
      } else {
        passwordField.select();
        passwordField.setSelectionRange(0, pw.length);
        if (!document.execCommand("copy")) {
          throw new Error("execCommand copy failed");
        }
      }
      setStatus("Copied to clipboard!", false);
    } catch (err) {
      setStatus("Copy failed. Select the password and copy it manually.", true);
    }
  }

  generateBtn.addEventListener("click", showNewPassword);
  copyBtn.addEventListener("click", copyPassword);

  // Clicking or focusing the field selects everything for easy manual copying
  passwordField.addEventListener("focus", () => passwordField.select());

  // Generate a password as soon as the page loads
  showNewPassword();
})();
