# indx

NTFS directory indexes (`$I30`), for forensics: every entry of a folder's index with the `$FILE_NAME` it holds (the file's record, its folder, four times, sizes, attributes, name), and the entries left in the index blocks' slack: files deleted or renamed since, and stale copies moved when the index was rebalanced. A folder's slack often names files the MFT no longer has. One dependency, its sibling `sootmark-common` (times, UTF-16).

```toml
[dependencies]
sootmark-indx = "0.1"
```

```rust
let index = indx::read_allocation(&std::fs::read("I30.bin")?);
for entry in index.slack() {
    println!("{} {:?} {:?}", entry.name, entry.parent, entry.modified);
}
```

## What you get

- `read_allocation(data)`: an `$INDEX_ALLOCATION:$I30` attribute's `INDX` blocks (update sequence fixups applied, torn blocks reported), each with its VCN, its entries in order and the entries carved from its slack.
- `read_root(data)`: an `$INDEX_ROOT:$I30` attribute's value: a small folder's only node, and its slack.
- `Entry`: the file's reference (record and sequence number; none for a slack entry whose header was overwritten), the folder's reference, created, modified, record changed and accessed (UTC), allocated and real sizes, attributes (`is_folder()`), namespace (POSIX, Win32, DOS, both) and name.
- Slack carving: at each 8-byte boundary past the used size, a whole entry, or a `$FILE_NAME` alone where the entry's header was overwritten, kept when its name and four times are plausible (1990 to 2100).
- Damage goes to `problems`, never a panic.

## How it's checked

- A volume written for these tests (`tests/fixtures/written/`: mkntfs, 300 files, 40 deleted): the folder's 260 live entries are the names The Sleuth Kit lists, and the names of all 40 deleted files are recovered from its slack, as Python alone finds them there (`tests/oracle/slack_names.py`, fixups undone independently).
- go-ntfs's test volume (Apache-2.0, `tests/fixtures/go-ntfs/`): the root folder's entries are the names The Sleuth Kit lists, and `.`.
- Property tests: damaged blocks give entries, problems or nothing, never a panic.

## Not yet

- Other indexes (`$SDH`, `$SII`, `$O`, `$Q`, `$R`): their keys aren't file names.
- Finding the attribute in a volume: the caller passes the attribute's data (`sootmark-disk` reads volumes).

## Licence

MIT or Apache-2.0, at your option.
