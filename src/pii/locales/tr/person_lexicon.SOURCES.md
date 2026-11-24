# person_names.txt, person_words.txt, person_context.txt - provenance

The three data files of the Turkish person-name lexicon
(`person_lexicon.rs`), compiled into the crate with `include_str!`. Each
file holds `#` comment lines, `@flags` section lines and one folded key
per line (lowercase ASCII; the Turkish letters with diacritics map to
their base letter, the circumflexes are dropped).

The files were generated on 2026-11-23 by a build script kept outside
this repository (the repository is Rust-only), from the two
upstream clones below, in a container without network access. The
sources were downloaded in a separate container into a new empty folder.

## person_names.txt (MIT License)

**Source:** `mkozturk/trnames` by Kaan Öztürk,
<https://github.com/mkozturk/trnames>, commit
`8bc31fafc71a090dcc6f80c540b8cfac84129ab1` (2021-02-14), retrieved
2026-11-23. Files and SHA-256:

| file | SHA-256 |
|---|---|
| `trnames/female_first.csv` | `aa2b63496820f7834fc60199001f1db198ae679556479a6c38c4670a4b626ca6` |
| `trnames/male_first.csv` | `036374ac5cadd0b029401cc1e010486b457d4761182b2b6f48ea7c3b8c35db38` |
| `trnames/all_last.csv` | `780de6fd605c7736f1f8f1d5c5b29ca52e032b679bb0cc63e0b6836983ef34e9` |
| `LICENSE` | `c5c83cb370b4ac3d2e39dec2945e3821fa164ae5c2cc0b7706168b5821251366` |

Upstream describes the data as first and last names "parsed from
49,611,709 individuals ... born between 1888 and 1991", names seen in
fewer than 100 individuals left out. The CSV files list each name
(upper-case ASCII) with its cumulative population share.

**Licence:** MIT License (upstream `LICENSE`, verified in the clone):
"Copyright (c) 2021 Kaan Öztürk". The full licence text is reproduced in
the repository `NOTICE` file.

**What was derived:** every letter-only name (25 rows holding initials
such as `M.` or `M.ALI` were dropped), lowercased, with four flags: `F`
first name (in either first-name file), `L` last name, `c` common
(population share at least 1e-4 as a first or as a last name; the share
of a row is the difference of consecutive cumulative values), `p`
first-name share at least the last-name share. 33,861 keys, 257,689
bytes, SHA-256
`a3269dc06a4c96f21bbe10a7ef92496cdc7ea41fb712d54cd4d6563e68c0f7ab`.

## person_words.txt (Apache License 2.0)

**Source:** Zemberek-NLP by Ahmet A. Akın and Mehmet D. Akın,
<https://github.com/ahmetaa/zemberek-nlp>, commit
`db0a556170b9f0aa6835eabee439930f786e58d8` (2026-11-23), retrieved
2026-11-23. Files (under `morphology/src/main/resources/tr/`) and
SHA-256:

| file | SHA-256 |
|---|---|
| `master-dictionary.dict` | `d41e33727a404d25574dadcb8c324d0c4d8e04f7ef9993d26011cff6f3d0feaa` |
| `non-tdk.dict` | `bd67856b1d7e101a30660b62677f3f075eaa24420433aec6741a14c9fba04ed1` |
| `proper.dict` | `5704f4017854c474442cce246443b9fec5967799a968ab9d7eb0cce930e32178` |
| `first-10K` | `0264f2f84424c160cc3e85578092011040038b782c8f6df92d53c1359f32b414` |
| `LICENSE` (repository root) | `c55ac4a942b0e8dc83833680e4afefc5b0ef8a5bc0d17e1addb3c98e235ea07a` |

**Licence:** Apache License 2.0 (upstream root `LICENSE`, verified in
the clone: "Copyright 2018 Ahmet A. Akın, Mehmet D. Akın"). The upstream
repository has no NOTICE file. A copy of the licence is in this
repository as `LICENSE-APACHE`.

**Changes (Apache-2.0 section 4(b) notice):** the file is a derived
word list, not a copy. Keys are folded as above; only these flags are
kept: `w` the lowercase form is among the 10,000 most frequent tokens
(`first-10K`), `m` a name key that is a lowercase headword of
`master-dictionary.dict` or `non-tdk.dict`, `i` a name key that is such a
headword plus one of 59 case or derivational suffixes (stem of at least
three letters, a final `b`/`d`/`g` read as `p`/`t`/`k`), `n` a proper noun
of `proper.dict`. Keys longer than 20 letters or with other characters
are dropped. 15,330 keys, 116,095 bytes, SHA-256
`fcd07185d02c025bd51f4017d11389318dd8cf74ef07dbcb62e2919ec42fc816`.

## person_context.txt (project-curated)

Written for this repository by the redactify contributors (licensed like
the crate, MIT OR Apache-2.0): 22 honorifics and titles before a name
(`h`), 15 honorifics and kinship words after a name (`b`), 4 greetings (`g`) and 127
organisation and address words (`o`). SHA-256
`03dac8537f77586793e59ed89140bcaf418126608e2fdc170d515fbee71b6d5b`.

## Excluded on purpose

No word list under a share-alike or non-commercial licence is used. In
particular the OpenSubtitles frequency list that other Turkish name
detectors ship (`FrequencyWords`, CC BY-SA 4.0) is not used; the
"name that is also a word" evidence comes from Zemberek (Apache-2.0)
only.

## What it is not

A list of real persons: the names are population name statistics and
dictionary words, without any person attached.
