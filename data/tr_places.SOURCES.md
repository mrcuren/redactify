# tr_places - provenance of the Turkish province/district table

The table lives in `src/pii/locales/tr/places.rs` (generated, 979 folded
keys) and is used by the `tr` address and place-of-birth rules
(`src/pii/locales/tr/gazetteer.rs`).

- Upstream: `turkiye-api` by Ubeyde Emir Özdemir,
  <https://github.com/ubeydeozdmr/turkiye-api>
- Licence: MIT (GitHub licence API `spdx_id: MIT`; LICENSE file read at the
  pinned commit, reproduced below).
- Commit: `a0ad8351cb52153e7a92aa7ba9a5bc1e3294da8d` (committed
  2026-10-01T19:46:40Z), retrieved 2026-11-23.
- Files used (only the `name` field of each record):
  - `datasets/provinces.json`, 81 records, 48,728 bytes, SHA-256
    `321ca5425ba9bc4f51f13bbdfed2928ae42b163a8b99365105dc089da3ec047d`
  - `datasets/districts.json`, 973 records, 278,610 bytes, SHA-256
    `05fa3f22584ec729da8fa35a9d108ad2f39798c34436fdff0533ed6b407f1079`
  - `LICENSE`, SHA-256
    `dc465f3bf6ed4639e5b1152d9f71754fd4c1ee3c017add67d6a35623e55ad8ea`
- Transformation: each name is folded (Turkish letters to their ASCII base
  letter, lowercase: `İzmir` -> `izmir`), duplicates removed (51 districts
  are named `Merkez`), sorted bytewise. The generator is a small script kept
  outside this repository (the repository holds Rust code only); re-running
  it on the files above reproduces `places.rs` byte for byte.
- Not used: neighbourhoods, villages, coordinates, populations, postal codes.

## Upstream licence (verbatim)

```text
MIT License

Copyright (c) 2022-2026 Ubeyde Emir Özdemir

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
