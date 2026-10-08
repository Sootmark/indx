//! A folder's index from a volume written for these tests
//! (`tests/fixtures/written/`, see its NOTICE): its live entries as The
//! Sleuth Kit lists the folder, and every deleted file whose name its
//! slack keeps (`tests/oracle/deleted-in-slack.txt`, found by
//! `tests/oracle/slack_names.py`); and go-ntfs's root folder (Apache-2.0,
//! `tests/fixtures/go-ntfs/`).

use std::collections::BTreeSet;

use proptest::prelude::*;

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// The live names The Sleuth Kit lists: `r/r 65-128-2:\treport_001.txt`,
/// deleted (`*`) lines left out, a stream (`$Secure:$SDS`) as its file.
fn fls_names(listing: &str) -> BTreeSet<String> {
    listing
        .lines()
        .filter(|l| !l.contains(" * ") && !l.starts_with("V/V"))
        .filter_map(|l| l.split_once(":\t").map(|(_, name)| name))
        .map(|name| name.split(':').next().unwrap_or(name).to_owned())
        .collect()
}

#[test]
fn live_entries_as_the_sleuth_kit_lists_them_and_deleted_names_in_slack() {
    let index = indx::read_allocation(&fixture("written/docs_I30.bin"));
    assert_eq!(index.problems, Vec::<String>::new());
    let live: BTreeSet<String> = index.entries().map(|e| e.name.clone()).collect();
    let listing = String::from_utf8(fixture("written/docs_fls.txt")).unwrap();
    assert_eq!(live, fls_names(&listing));
    assert_eq!(index.entries().count(), 260);

    let deleted: BTreeSet<String> = include_str!("oracle/deleted-in-slack.txt")
        .lines()
        .map(str::to_owned)
        .collect();
    let carved: BTreeSet<String> = index
        .slack()
        .map(|e| e.name.clone())
        .filter(|name| !live.contains(name))
        .collect();
    assert_eq!(carved, deleted);
    let gone = index.slack().find(|e| e.name == "report_050.txt").unwrap();
    assert!(gone.modified.is_some() && !gone.is_folder());

    let root = indx::read_root(&fixture("written/docs_root.bin"));
    assert_eq!(root.problems, Vec::<String>::new());
    assert_eq!(
        root.entries().count(),
        0,
        "a large folder's root keeps only its end entry"
    );
}

#[test]
fn a_root_folder() {
    let index = indx::read_allocation(&fixture("go-ntfs/root_I30.bin"));
    assert_eq!(index.problems, Vec::<String>::new());
    let mut names: BTreeSet<String> = index.entries().map(|e| e.name.clone()).collect();
    assert!(names.remove("."), "the root lists itself");
    let listing = String::from_utf8(fixture("go-ntfs/root_fls.txt")).unwrap();
    assert_eq!(names, fls_names(&listing));
}

proptest! {
    #[test]
    fn damaged_blocks_read_without_panic(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..64),
        cut in any::<usize>(),
    ) {
        let mut data = fixture("written/docs_I30.bin");
        for (at, byte) in flips {
            let at = at % data.len();
            data[at] = byte;
        }
        data.truncate(cut % (data.len() + 1));
        let _ = indx::read_allocation(&data);
        let _ = indx::read_root(&data);
    }
}
