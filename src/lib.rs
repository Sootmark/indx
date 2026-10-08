//! NTFS directory indexes, for forensics: the `$I30` index of a folder
//! (its `$INDEX_ROOT` attribute and, for larger folders, its
//! `$INDEX_ALLOCATION` of 4096-byte `INDX` blocks), every entry with the
//! `$FILE_NAME` it holds (the file's record, its folder, four times, sizes,
//! attributes, name), and the entries left in the blocks' slack: files
//! deleted or renamed since, and stale copies moved when the index was
//! rebalanced. A folder's slack often names files the MFT no longer has.
//!
//! An `INDX` block is protected like an MFT record by an update sequence
//! array (the last two bytes of each 512-byte sector saved in it). After
//! its header comes a node header (where entries start, how many bytes
//! they use, how many are allocated, whether the node has children), then
//! entries, each: the file's reference, the entry's length, the key's
//! length, flags (1: a child node's VCN follows; 2: the last entry, with no
//! key), the key (a
//! `$FILE_NAME` value), and for a node with children the child's VCN in
//! its last 8 bytes. Bytes past the used size, up to the allocated size,
//! are slack: what earlier entries left there.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let index = indx::read_allocation(&std::fs::read("I30.bin")?);
//! for entry in index.blocks.iter().flat_map(|b| &b.slack) {
//!     println!("{} {:?}", entry.name, entry.modified);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Damage goes to `problems`, never a panic.

use common::time::Ts;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The size of an index block.
pub const BLOCK_SIZE: usize = 4096;
/// The block's header up to the node header.
const NODE_HEADER_AT: usize = 0x18;
/// An entry's fixed part before its key.
const ENTRY_HEADER: usize = 0x10;
/// A `$FILE_NAME` value's fixed part before the name.
const FILE_NAME_HEADER: usize = 0x42;
/// The entry flag marking the node's last (keyless) entry.
const LAST: u32 = 0x02;
/// FILETIMEs of plausible slack entries: 1990 to 2100.
const PLAUSIBLE: core::ops::Range<u64> = 0x01B6_4B40_0000_0000..0x0233_2C9D_0000_0000;

/// A file reference: an MFT record number and its sequence number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Reference {
    /// The MFT record number.
    pub entry: u64,
    /// The record's sequence number.
    pub sequence: u16,
}

impl Reference {
    fn from_raw(raw: u64) -> Self {
        Self {
            entry: raw & 0x0000_FFFF_FFFF_FFFF,
            sequence: (raw >> 48) as u16,
        }
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.entry, self.sequence)
    }
}

/// An index entry: a name of a file in the folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its offset in the data read.
    pub offset: usize,
    /// The file it names (from the entry's header; for a slack entry whose
    /// header was overwritten, none).
    pub file: Option<Reference>,
    /// The folder it is in.
    pub parent: Reference,
    /// Created, as recorded with the name (UTC).
    pub created: Option<Ts>,
    /// Content last modified.
    pub modified: Option<Ts>,
    /// File record last changed.
    pub changed: Option<Ts>,
    /// Last accessed.
    pub accessed: Option<Ts>,
    /// Allocated size, in bytes.
    pub allocated_size: u64,
    /// Real size, in bytes.
    pub size: u64,
    /// The file's attributes (`FILE_ATTRIBUTE_*`, `0x1000_0000` a folder).
    pub attributes: u32,
    /// The naming rules: 0 POSIX, 1 Win32, 2 DOS, 3 Win32 and DOS.
    pub namespace: u8,
    /// The name.
    pub name: String,
}

impl Entry {
    /// Whether it names a folder.
    #[must_use]
    pub fn is_folder(&self) -> bool {
        self.attributes & 0x1000_0000 != 0
    }
}

/// An `INDX` block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Block {
    /// Its offset in the data read.
    pub offset: usize,
    /// Its VCN in the index.
    pub vcn: u64,
    /// The entries it holds, in order.
    pub entries: Vec<Entry>,
    /// The entries found in its slack.
    pub slack: Vec<Entry>,
}

/// An index's blocks and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    /// The blocks, in order.
    pub blocks: Vec<Block>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl Index {
    /// Every entry the blocks hold.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.blocks.iter().flat_map(|b| &b.entries)
    }

    /// Every entry found in slack.
    pub fn slack(&self) -> impl Iterator<Item = &Entry> {
        self.blocks.iter().flat_map(|b| &b.slack)
    }
}

/// Read an `$INDEX_ALLOCATION` attribute's data: its `INDX` blocks, the
/// entries they hold and those left in their slack.
#[must_use]
pub fn read_allocation(data: &[u8]) -> Index {
    let mut index = Index::default();
    for (number, raw) in data.chunks(BLOCK_SIZE).enumerate() {
        let offset = number * BLOCK_SIZE;
        if !raw.starts_with(b"INDX") {
            continue;
        }
        let mut block = raw.to_vec();
        if let Err(why) = apply_fixups(&mut block) {
            index.problems.push(format!("block at {offset:#x}: {why}"));
            continue;
        }
        match read_block(&block, offset) {
            Ok(parsed) => index.blocks.push(parsed),
            Err(why) => index.problems.push(format!("block at {offset:#x}: {why}")),
        }
    }
    index
}

/// Read an `$INDEX_ROOT` attribute's value: the entries the root node
/// holds (a small folder's only node).
#[must_use]
pub fn read_root(data: &[u8]) -> Index {
    let mut index = Index::default();
    // The root's header (attribute type, collation, block size, clusters
    // per block) comes before the node header.
    match node(data, 0x10, 0) {
        Ok((entries, slack)) => index.blocks.push(Block {
            offset: 0,
            vcn: 0,
            entries,
            slack,
        }),
        Err(why) => index.problems.push(format!("index root: {why}")),
    }
    index
}

/// Undo the update sequence array: check each sector's last two bytes
/// against the sequence number and put back the saved ones.
fn apply_fixups(block: &mut [u8]) -> Result<(), String> {
    let array_offset = usize::from(u16_at(block, 4).ok_or("a header cut short")?);
    let count = usize::from(u16_at(block, 6).ok_or("a header cut short")?);
    if count < 2 {
        return Err("no update sequence array".to_owned());
    }
    let sequence = u16_at(block, array_offset).ok_or("an update sequence array past the end")?;
    for sector in 1..count {
        let end = sector * 512;
        let saved = u16_at(block, array_offset + 2 * sector)
            .ok_or("an update sequence array past the end")?;
        if end > block.len() {
            break;
        }
        if u16_at(block, end - 2) != Some(sequence) {
            return Err(format!(
                "sector {sector} torn (its sequence number differs)"
            ));
        }
        block[end - 2..end].copy_from_slice(&saved.to_le_bytes());
    }
    Ok(())
}

/// A fixed-up block's entries and slack.
fn read_block(block: &[u8], offset: usize) -> Result<Block, String> {
    let vcn = u64_at(block, 0x10).ok_or("a header cut short")?;
    let (entries, slack) = node(block, NODE_HEADER_AT, offset)?;
    Ok(Block {
        offset,
        vcn,
        entries,
        slack,
    })
}

/// The entries of the node whose header is at `at`, and those in its slack.
fn node(data: &[u8], at: usize, base: usize) -> Result<(Vec<Entry>, Vec<Entry>), String> {
    let short = || "a node header cut short".to_owned();
    let start = at + u32_at(data, at).ok_or_else(short)? as usize;
    let used = at + u32_at(data, at + 4).ok_or_else(short)? as usize;
    let allocated = at + u32_at(data, at + 8).ok_or_else(short)? as usize;
    let used = used.min(data.len());
    let allocated = allocated.min(data.len()).max(used);
    let mut entries = Vec::new();
    let mut cursor = start;
    while cursor + ENTRY_HEADER <= used {
        let length = usize::from(u16_at(data, cursor + 8).ok_or_else(short)?);
        let flags = u32_at(data, cursor + 12).ok_or_else(short)?;
        if flags & LAST != 0 || length < ENTRY_HEADER {
            break;
        }
        let entry_data = data
            .get(cursor..cursor + length)
            .ok_or_else(|| format!("an entry at {:#x} past the node's end", base + cursor))?;
        let entry = entry(entry_data, base + cursor)
            .ok_or_else(|| format!("an entry at {:#x} that isn't a file name", base + cursor))?;
        entries.push(entry);
        cursor += length;
    }
    let slack = data
        .get(used..allocated)
        .map_or_else(Vec::new, |s| carve(s, base + used));
    Ok((entries, slack))
}

/// An entry from its bytes (header and key).
fn entry(data: &[u8], offset: usize) -> Option<Entry> {
    let file = Reference::from_raw(u64_at(data, 0)?);
    let key_length = usize::from(u16_at(data, 10)?);
    let key = data.get(ENTRY_HEADER..ENTRY_HEADER.checked_add(key_length)?)?;
    let mut parsed = file_name(key, offset + ENTRY_HEADER)?;
    parsed.offset = offset;
    parsed.file = Some(file);
    Some(parsed)
}

/// A `$FILE_NAME` value.
fn file_name(key: &[u8], offset: usize) -> Option<Entry> {
    let length = usize::from(*key.get(0x40)?);
    let namespace = *key.get(0x41)?;
    let name = key.get(FILE_NAME_HEADER..FILE_NAME_HEADER + 2 * length)?;
    let time = |at: usize| u64_at(key, at).filter(|&t| t != 0).map(Ts::from_filetime);
    Some(Entry {
        offset,
        file: None,
        parent: Reference::from_raw(u64_at(key, 0)?),
        created: time(0x08),
        modified: time(0x10),
        changed: time(0x18),
        accessed: time(0x20),
        allocated_size: u64_at(key, 0x28)?,
        size: u64_at(key, 0x30)?,
        attributes: u32_at(key, 0x38)?,
        namespace,
        name: common::text::utf16le(name).text,
    })
}

/// The entries in a node's slack: at each 8-byte boundary, a whole entry
/// (header and key) or, where the header was overwritten, a key alone,
/// kept when its name and times are plausible.
fn carve(slack: &[u8], base: usize) -> Vec<Entry> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + FILE_NAME_HEADER <= slack.len() {
        let whole = slack.get(at..).and_then(|rest| {
            let length = usize::from(u16_at(rest, 8)?);
            let key_length = usize::from(u16_at(rest, 10)?);
            (key_length >= FILE_NAME_HEADER && length >= ENTRY_HEADER + key_length)
                .then(|| entry(rest, base + at))
                .flatten()
                .filter(plausible)
        });
        if let Some(entry) = whole {
            let length = ENTRY_HEADER + FILE_NAME_HEADER + 2 * entry.name.encode_utf16().count();
            found.push(entry);
            at += length.next_multiple_of(8);
            continue;
        }
        if let Some(key) = slack
            .get(at..)
            .and_then(|rest| file_name(rest, base + at))
            .filter(plausible)
        {
            let length = FILE_NAME_HEADER + 2 * key.name.encode_utf16().count();
            found.push(key);
            at += length.next_multiple_of(8);
            continue;
        }
        at += 8;
    }
    found
}

/// Whether a carved entry looks like a real name: a known namespace, a
/// non-empty name without NULs, separators or escaped bytes, and its four
/// times between 1990 and 2100.
fn plausible(entry: &Entry) -> bool {
    let times = [entry.created, entry.modified, entry.changed, entry.accessed];
    let filetimes_ok = times.iter().all(|t| {
        t.and_then(|t| t.ticks())
            .and_then(|ticks| u64::try_from(ticks + 116_444_736_000_000_000).ok())
            .is_some_and(|ft| PLAUSIBLE.contains(&ft))
    });
    entry.namespace <= 3
        && !entry.name.is_empty()
        && !entry.name.contains(['\0', '\\', '/'])
        && !entry.name.contains("\\u{")
        && filetimes_ok
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_split() {
        let r = Reference::from_raw(0x0002_0000_0000_0041);
        assert_eq!((r.entry, r.sequence), (0x41, 2));
        assert_eq!(r.to_string(), "65-2");
    }

    #[test]
    fn other_data() {
        assert!(read_allocation(b"not an index").blocks.is_empty());
        assert!(!read_root(b"short").problems.is_empty());
    }
}
