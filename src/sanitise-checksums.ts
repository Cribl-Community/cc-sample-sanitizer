// ============================================================================
// sanitise-checksums.ts — payment cards, IBANs and phone numbers, found by structure
// ============================================================================
//
// The secret-rules library already carries card and IBAN patterns, but as `numeric` /
// `structured` rules they only fire with a context keyword ("card", "iban") in the 40
// characters before the match. That is the right gate for a pattern that is just a digit run
// — and the wrong one for a value that carries its OWN proof. A card number has a Luhn check
// digit and a registered issuer prefix; an IBAN has a mod-97 checksum and a fixed length per
// country. A random 16-digit id passes both card tests about once in a hundred, and a random
// IBAN-shaped string passes about once in a hundred thousand, so these are found wherever
// they sit — `pan 4111…`, a bare payout line, a JSON value — keyword or not.
//
// Phone numbers have no checksum, so only the international form is taken: a leading `+`,
// a country code that does not start with 0, and 8–15 digits. A number written with no
// separators still needs a keyword nearby, because `+12345678` is as likely a counter delta.
//
// No imports: reachable from the AI-free sanitizer build and from a plain Node script alike.

/** Luhn (mod-10) check over a digit string. */
export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Issuer prefix and length of the card networks that publish their ranges.
 *
 * Luhn alone passes one number in ten, and logs are full of 16-digit ids. Requiring a real
 * issuer prefix at its network's length is what turns "passes a checksum" into "is shaped
 * like a card": most ids start with 1 (epoch timestamps, snowflake ids) and none of those
 * are issued.
 *
 * Only the lengths cards are actually issued at in volume — 16, Amex's 15, Diners' 14. The
 * networks also allow 13 and 17–19, but against the shipped corpus those lengths matched
 * nothing but EDR process ids (CrowdStrike's 13-, 18- and 19-digit ids pass Luhn one time in
 * ten, like any number), so a rare real card is traded for not flooding the review.
 */
export function cardIssuerMatches(digits: string): boolean {
  const n = digits.length;
  const p2 = Number(digits.slice(0, 2));
  const p3 = Number(digits.slice(0, 3));
  const p4 = Number(digits.slice(0, 4));
  if (digits[0] === '4') return n === 16;                                         // Visa
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return n === 16;     // Mastercard
  if (p2 === 34 || p2 === 37) return n === 15;                                    // Amex
  if (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649)) return n === 16;     // Discover
  if (p4 >= 3528 && p4 <= 3589) return n === 16;                                 // JCB
  if (p2 === 36 || p2 === 38 || (p3 >= 300 && p3 <= 305)) return n === 14 || n === 16;  // Diners
  if (p2 === 62) return n === 16;                                                 // UnionPay
  return false;
}

/* A contiguous 14–16 digit run, or the printed forms: 4-4-4-4 with one consistent separator,
   and Amex's 4-6-5. Not inside a longer word, number or dotted value. */
const CARD_RE = /(?<![\w.+-])(?:\d{14,16}|\d{4}([ -])\d{4}\1\d{4}\1\d{4}|\d{4}([ -])\d{6}\2\d{5})(?![\w]|[.-]\d)/g;
/* The value of a field whose name ends in "id" — `TargetProcessId`, `session_id`. Cards live
   in `pan`, `card_number`, `cc`; an id field holding a Luhn-valid number is an id. */
const ID_FIELD_BEFORE = /(?:id|Id|ID)["']?\s*[:=]\s*["']?$/;

/** Card numbers on a line, exactly as written (separators included). */
export function findCardNumbers(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(CARD_RE)) {
    if (ID_FIELD_BEFORE.test(line.slice(Math.max(0, m.index! - 40), m.index))) continue;
    const digits = m[0].replace(/[ -]/g, '');
    if (cardIssuerMatches(digits) && luhnValid(digits)) out.push(m[0]);
  }
  return out;
}

/* Registered IBAN length per country (SWIFT IBAN registry). A wrong length for the country
   code is rejected before the checksum is even computed. */
const IBAN_LENGTH: Record<string, number> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28,
  CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18,
  FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28, IE: 22,
  IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20,
  LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15,
  PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SC: 31, SE: 24, SI: 19,
  SK: 24, SM: 27, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
};

/** Country length and ISO 13616 mod-97 check. Spaces are ignored. */
export function ibanValid(raw: string): boolean {
  const iban = raw.replace(/ /g, '');
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) return false;
  if (IBAN_LENGTH[iban.slice(0, 2)] !== iban.length) return false;
  const moved = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;   // A=10 … Z=35
    for (const d of v) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

/* Compact, or printed in groups of four with single spaces. */
const IBAN_RE = /(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)(?![A-Za-z0-9])/g;

/** IBANs on a line, exactly as written. */
export function findIbans(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(IBAN_RE)) {
    /* The grouped form can run on into an uppercase word after it — `NL91 ABNA 0417 1643 00
       OK` — so a failed check drops trailing groups before giving up. */
    let cand = m[0];
    while (!ibanValid(cand) && cand.includes(' ')) cand = cand.slice(0, cand.lastIndexOf(' '));
    if (ibanValid(cand)) out.push(cand);
  }
  return out;
}

/* `+`, a country code not starting with 0, then digits with space, dot, dash or bracket
   separators. A separator only counts when a digit follows, so a sentence's full stop or a
   trailing dash is never swallowed. */
const PHONE_RE = /(?<![\w+])\+[1-9](?:\d|[ .-](?=[\d(])|\((?=\d)|\)(?=[ .-]?\d))*/g;
/* `10:00:00 +1000` is a timezone, not a number. */
const TIME_BEFORE = /\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?\s?$/;
const PHONE_WORDS = /(?:phone|tel|mobile|msisdn|cell|fax|sms|whatsapp|call|contact)/i;
const PHONE_WINDOW = 40;

/** International phone numbers on a line, exactly as written. */
export function findPhoneNumbers(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(PHONE_RE)) {
    let cand = m[0];
    const before = line.slice(Math.max(0, m.index! - PHONE_WINDOW), m.index);
    if (TIME_BEFORE.test(before)) continue;
    /* A trailing space-separated group after a number written with dashes or dots belongs
       to the next field — `+1-415-555-0132 22` is a number and then a port. */
    const seps = cand.match(/[ .-]/g) || [];
    if (seps.length >= 2 && seps[seps.length - 1] === ' ' && seps.slice(0, -1).some(s => s !== ' ')) {
      cand = cand.slice(0, cand.lastIndexOf(' '));
    }
    const digits = cand.replace(/\D/g, '');
    if (digits.length < 8 || digits.length > 15) continue;
    if (!/[ ().-]/.test(cand) && !PHONE_WORDS.test(before)) continue;
    out.push(cand);
  }
  return out;
}
