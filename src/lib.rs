mod args;
mod error;

use std::{
    fs::File,
    io::{BufReader, ErrorKind},
    path::PathBuf,
};

use anyhow::{Context, Result};
pub use args::Config;
pub use error::GrepError;
use rand::seq::IndexedRandom;
use std::io::{BufRead, Read};

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
    let regex_pattern = regex::RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .context("pattern is invalid")?;
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
/// This function will skip binary files to avoid UTF-8 encoding errors.
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
    println!("\nScanning file: {}", path.display());

    // Check if file is likely to be a text file by reading first few bytes
    if !is_likely_text_file(path)? {
        return Ok(());
    }
    
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
            println!("#{}: {}", line_number + 1, highlight_line(&line, re));
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

/// Check if a file looks like UTF-8 encoded text.
/// 
/// This function reads the first 1KB of the file and checks if it can be decoded as UTF-8.
/// If not, it falls back to a heuristic that checks if the file contains a high proportion of printable characters.
/// 
/// # Examples
/// 
/// ```
/// use minigrep::is_likely_text_file;
/// 
/// let path = PathBuf::from("example");
/// let result = is_likely_text_file(&path);
/// assert!(result.is_ok());
/// ```
fn is_likely_text_file(path: &PathBuf) -> Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0; 1024]; // 采样前 1KB 内容
    let n = file.read(&mut buffer)?;
    Ok(std::str::from_utf8(&buffer[..n]).is_ok() || looks_like_text(&buffer[..n]))
}

/// Check if a file looks like text.
/// 
/// This function reads the first 1KB of the file and checks if it can be decoded as UTF-8.
/// If not, it falls back to a heuristic that checks if the file contains a high proportion of printable characters.
/// 
/// # Examples
/// 
/// ```
/// use minigrep::looks_like_text;
/// 
/// let path = PathBuf::from("example");
/// let result = looks_like_text(&path);
/// assert!(result.is_ok());
/// ```
fn looks_like_text(data: &[u8]) -> bool {
    let printable = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r').count();
    printable as f32 / data.len() as f32 > 0.95
}

/// Highlight a line of text using a regular expression.
/// 
/// This function takes a line of text and a regular expression, and returns a new string with the matches highlighted.
/// 
/// # Examples
/// 
/// ```
/// use minigrep::highlight_line;
/// 
/// let line = "Hello, world!";
/// let re = regex::Regex::new(r"world").unwrap();
/// let result = highlight_line(line, &re);
/// assert_eq!(result, "Hello, \x1b[31mworld\x1b[0m!");
/// ```
fn highlight_line(line: &str, re: &regex::Regex) -> String {
    let mut highlighted = String::new();
    let mut last_end = 0;
    let colors = vec!["\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m", "\x1b[37m", "\x1b[97m"];
    let mut rng = rand::rng();
    for (_i, cap) in re.find_iter(line).enumerate() {
        let start = cap.start();
        let end = cap.end();
        
        // keep unmatched beginnings
        highlighted.push_str(&line[last_end..start]);
        
        // hilight the matched section
        highlighted.push_str(&colors.choose(&mut rng).unwrap());
        highlighted.push_str(&line[start..end]);
        highlighted.push_str("\x1b[0m");
        last_end = end;
    }
    
    // add remaining text
    highlighted.push_str(&line[last_end..]);
    
    highlighted
}

