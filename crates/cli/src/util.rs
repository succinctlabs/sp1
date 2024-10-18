use std::path::{Path, PathBuf};
use std::{fmt::Display, time::Duration};

pub(crate) fn write_status(style: &dyn Display, status: &str, msg: &str) {
    println!("{style}{status:>12}{style:#} {msg}");
}

pub(crate) fn elapsed(duration: Duration) -> String {
    let secs = duration.as_secs();

    if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}.{:02}s", secs, duration.subsec_nanos() / 10_000_000)
    }
}

/// Create a canonical path from a given path.
///
/// This function will create any necessary directories in the path if they do not exist.
///
/// This function does not guarntee that the file or directory exists, only that the path is valid.
/// (ie. [std::fs::File::create] and [std::fs::DirBuilder::create] will work)
pub(crate) fn canon_path(path: impl AsRef<Path>) -> Result<PathBuf, std::io::Error> {
    let path = path.as_ref();

    // in case this is a file, we only need to ensure its parent directorys are created
    if path.components().count() > 1 {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            // unwrap: we know we have a last component because we have a parent
            let last_component = path.components().last().unwrap();

            return Ok(parent
                .canonicalize()
                .inspect_err(|_| {
                    eprintln!("Failed to canonicalize parent directory: {:?}", parent);
                })?
                .join(last_component));
        }
    }

    if !path.has_root() {
        // we dont have a parent or a root,
        // so lets just adjoin it to the currnet working dir
        return Ok(std::env::current_dir()?.join(path));
    }

    // we didnt have a parent, and we have root
    // so this can only be the root dir
    return Ok(path.to_path_buf());
}
