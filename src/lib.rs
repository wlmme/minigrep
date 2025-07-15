mod args;
mod error;

use std::{fs::File, io::{BufReader, ErrorKind}, path::PathBuf};

use anyhow::{Context, Result};
pub use args::Config;
pub use error::GrepError;
use std::io::BufRead;

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

    // if path is None then search current directory else search in the given path
    if path.is_none() {
        let current_dir = std::env::current_dir().context("failed to get current directory")?;
        let path = PathBuf::from(current_dir);
        search_in_directory(&regex_pattern, &path, recursive)?;
    } else {
        let paths: Vec<PathBuf> = path
            .unwrap()
            .iter()
            .map(|s| -> PathBuf { PathBuf::from(s) })
            .collect();
        if paths.is_empty() {
            // if no path is provided, search current directory
            let current_dir = std::env::current_dir().context("failed to get current directory")?;
            let path = PathBuf::from(current_dir);
            search_in_directory(&regex_pattern, &path, recursive)?;
        }
        for path in paths {
            if path.is_file() {
                search_in_directory(&regex_pattern, &path, recursive)?;
            } else if path.is_dir() {
                search_in_directory(&regex_pattern, &path, recursive)?;
            }
        }
    }

    Ok(())
}

/// Search for a pattern in a file.
///
/// This function takes a regular expression and a file path as input and searches for the pattern in the file.
/// If the pattern is found, it prints the file path and the line number along with the matched line.
///
/// # Examples
///
/// ```
/// use minigrep::search_in_file;
///
/// let regex_pattern = regex::Regex::new(r"pattern").unwrap();
/// let path = PathBuf::from("path/to/file");
///
/// search_in_file(&regex_pattern, &path).unwrap();
/// ```
///
/// # Errors
///
/// This function will return an error if the file cannot be read or if the regular expression is invalid.
fn search_in_file(re: &regex::Regex, path: &PathBuf) -> Result<()> {
    let file = File::open(path)
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => GrepError::FileNotFound {
                path: path.display().to_string(),
            },
            ErrorKind::PermissionDenied => GrepError::PermissionDenied {
                path: path.display().to_string(),
            },
            _ => GrepError::FileReadError {
                path: path.display().to_string(),
            },
        })
        .with_context(|| format!("failed to open file {}", path.display()))?;
    let capacity = determine_capacity(path)
        .with_context(|| format!("failed to get capacity for file {}", path.display()))?;
    let file_reader = BufReader::with_capacity(capacity, file);
    for (line_number, line) in file_reader.lines().enumerate() {
        let line = line.with_context(|| {
            format!(
                "failed to read line {} in file {}",
                line_number + 1,
                path.display()
            )
        })?;
        if re.is_match(&line) {
            println!("{}:{}: {}", path.display(), line_number + 1, line);
        }
    }
    Ok(())
}

/// Determine the capacity for a file based on its size.
///
/// # Errors
///
/// This function will return an error if the file cannot be read or if the regular expression is invalid.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use minigrep::determine_capacity;
///
/// let path = PathBuf::from("example.txt");
/// let capacity = determine_capacity(&path);
/// assert!(capacity.is_ok());
/// ```
fn determine_capacity(path: &PathBuf) -> Result<usize> {
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to get metadata for file {}", path.display()))?;
    let file_size = metadata.len();
    let capacity = match file_size {
        0..=16384 => 4 * 1024,
        16385..=524288 => 32 * 1024,
        _ => 128 * 1024,
    };
    Ok(capacity)
}

/// Search for a regular expression in a directory files.
///
/// This function will search for a regular expression in all files within a directory and its subdirectories.
///
/// # Errors
///
/// This function will return an error if the directory cannot be read or if the regular expression is invalid.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use minigrep::search_in_directory;
///
/// let path = PathBuf::from("example");
/// let regex = regex::Regex::new(r"example").unwrap();
/// let result = search_in_directory(&regex, &path, true);
/// assert!(result.is_ok());
/// ```
fn search_in_directory(regex: &regex::Regex, path: &PathBuf, recursive: bool) -> Result<()> {
    let entries = std::fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?;
    for entry in entries {
        let entry = entry
            .with_context(|| format!("failed to read entry in directory {}", path.display()))?;
        let path = entry.path();
        if path.is_dir() && recursive {
            search_in_directory(regex, &path, recursive)?;
        } else if path.is_file() {
            search_in_file(regex, &path)?;
        } else {
            // Ignore non-file entries, such as symbolic links.
        }
    }
    Ok(())
}
