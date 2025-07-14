mod args;
mod error;

use std::path::PathBuf;

use anyhow::{Context, Result};
pub use args::Config;
pub use error::GrepError;

/// Searches for a pattern in a file or directory.
///
/// This function takes a `Config` struct as input and returns a `Result` indicating success or failure.
/// The `Config` struct contains the pattern to search for, the path to search in, and flags for case-insensitive and recursive searches.
///
/// # Examples
///
/// ```
/// use minigrep::Config;
///
/// let config = Config::new("hello", "src");
/// let result = minigrep::greps(&config);
/// assert!(result.is_ok());
/// ```
pub fn greps<'a>(config: &'a Config) -> Result<()> {
    let pattern = config.pattern.as_str();
    let path = config.path.as_ref().or(None);
    let ignore_case = config.ignore_case;
    let recursive = config.recursive;

    // convert pattern to regex
    let regex_pattern = regex::Regex::new(pattern).context("pattern is invalid")?;

    if path.is_none() {
        let current_dir = std::env::current_dir().context("failed to get current directory")?;
        let files = current_dir
            .read_dir()
            .context("failed to read current directory")?;
        for entry in files {
            let path = entry.context("failed to get entry")?.path();
            if path.is_file() {
                let contents = std::fs::read_to_string(&path).context("failed to read file")?;
                let lines = contents.lines();
                for line in lines {
                    if regex_pattern.is_match(line) {
                        println!("{}: {}", path.display(), line);
                    }
                }
            }
        }
    } else {
        let path: Vec<PathBuf> = path.unwrap().iter().map(|s| -> PathBuf {
            PathBuf::from(s)
        }).collect();
        for path in path {
            if path.is_file() {
                let contents = std::fs::read_to_string(&path).context("failed to read file")?;
                let lines = contents.lines();
                for line in lines {
                    if regex_pattern.is_match(line) {
                        println!("{}: {}", path.display(), line);
                    }
                }
            } else if recursive {
                let files = path.read_dir().context("failed to read directory")?;
                for entry in files {
                    let path = entry.context("failed to get entry")?.path();
                    if path.is_file() {
                        let contents = std::fs::read_to_string(&path).context("failed to read file")?;
                        let lines = contents.lines();
                        for line in lines {
                            if regex_pattern.is_match(line) {
                                println!("{}: {}", path.display(), line);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
