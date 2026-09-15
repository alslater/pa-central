/** Unicode code point count, matching Python's `len()` (and therefore
 *  Pydantic's `Field(min_length=...)`) — not `String.prototype.length`,
 *  which counts UTF-16 code units. A character outside the Basic
 *  Multilingual Plane (most emoji) is a surrogate pair: `"😀".length`
 *  is 2, but both JS and Python agree it is one code point via
 *  `Array.from`/iteration. Six emoji are `"😀".repeat(6).length === 12`
 *  in JS but `len(...) == 6` in Python — using `.length` against a
 *  backend length constraint accepts client-side what the API then
 *  rejects. `Array.from` (not a manual loop) is what actually iterates
 *  by code point, including multi-code-point sequences like ZWJ emoji,
 *  matching Python's `len()` for those too. */
export function codePointLength(value: string): number {
  return Array.from(value).length
}

/** bcrypt's own hard limit (see backend core/security.py's
 *  MAX_PASSWORD_BYTES) — it hashes only the first 72 *bytes* of its input
 *  and raises rather than truncating past that, so every password field
 *  the backend passes to bcrypt rejects anything longer with a 422
 *  (_reject_password_over_bcrypt_limit in schemas/__init__.py). Counting
 *  UTF-8 *bytes*, not code points or JS string length: 40 "é" characters
 *  is only 40 code points but 80 UTF-8 bytes, well past this limit, while
 *  looking short to both `.length` and `codePointLength`. */
export const MAX_PASSWORD_BYTES = 72

/** UTF-8 byte length, matching what the backend actually measures against
 *  MAX_PASSWORD_BYTES — not `.length` (UTF-16 code units) or
 *  `codePointLength` (code points), either of which undercounts non-ASCII
 *  input relative to its encoded size. */
export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length
}
