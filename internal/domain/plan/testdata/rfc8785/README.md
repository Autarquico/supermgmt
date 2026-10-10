# RFC 8785 (JCS) test vectors

Source: RFC 8785, "JSON Canonicalization Scheme (JCS)", sections 3.2.2 to 3.2.4
and Appendix B (<https://www.rfc-editor.org/rfc/rfc8785>).

Plans forbid floats and restrict integers to `[0, 2^53-1]` (spec Appendix C), so
this package implements the whole of JCS except ECMAScript float formatting.
The vectors are therefore split in two:

- `applicable/` holds `NAME.input.json` / `NAME.expected.json` pairs. The test
  requires the canonical output to be byte-identical to `expected` (no trailing
  newline).
  - `sorting`: RFC section 3.2.3 property-sorting sample (UTF-16 code unit
    order; note U+1F600 sorts before U+FB33), expected order from the RFC.
  - `primitives`: RFC section 3.2.2 sample with the `numbers` member removed;
    expected output taken from the RFC (section 3.2.3).
  - `nesting`: not from the RFC; exercises "sort recursively, never reorder
    arrays" (section 3.2.3 rules).
- `rejected/` holds inputs that MUST fail. The test requires an error.
  - `numbers-section-3.2.2.json` and `appendix-b-numbers.txt` (one literal per
    line) contain the RFC's float samples and out-of-range integers. The RFC
    formats them; plans reject them by design. Note that Appendix B's
    `-0 -> 0` row is rejected too: negative numbers are not allowed.
  - `lone-*`, `high-surrogate-then-non-low`, `invalid-utf8`: RFC section
    3.2.2.2 says such data MUST cause an error.
  - `duplicate-keys*`, `trailing-data`, `negative-integer`: I-JSON (RFC 7493)
    and plan constraints.

The fixtures were generated with an independent Python implementation of the
rules (`ensure_ascii=False`-style output sorted by UTF-16 code units), not with
this package's code.
