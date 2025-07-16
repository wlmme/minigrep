

use std::{collections::HashSet, io::Read, path::PathBuf, sync::LazyLock};

use crate::FileInfo;
use anyhow::{Context, Result};
use rand::seq::IndexedRandom;

/// Binary extensions
/// 
/// This HashSet contains common file extensions that are typically associated with binary files.
/// These files are usually not human-readable and require specific software to open and view their contents.
/// 
/// This Set is used to determine if a file is binary or not.
static BINARY_EXTENSIONS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // Images
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "tiff", "svg", "webp",
        // Videos
        "mp4", "avi", "mov", "wmv", "flv", "webm", "mkv",
        // Audio
        "mp3", "wav", "flac", "aac", "ogg", "wma",
        // Archives
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
        // Executables
        "exe", "dll", "so", "dylib", "bin",
        // Documents
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        // Fonts
        "ttf", "otf", "woff", "woff2",
        // Other
        "db", "sqlite", "sqlite3", "lock",
    ]
    .into_iter()
    .collect()
});

/// Determines if a file is binary based on its extension.
/// 
/// This function checks if the file extension is in the set of known binary extensions.
/// If the extension is not found or the file has no extension, it is considered not binary.
/// 
/// # Arguments
/// 
/// * `path` - A reference to a `PathBuf` representing the file path.
/// 
/// # Returns
/// 
/// A boolean value indicating whether the file is binary or not
/// 
/// # Examples
/// 
/// ```
/// use std::path::PathBuf;
/// use minigrep::utils::is_binary_file_by_extension;
/// 
/// let path = PathBuf::from("example.png");
/// assert!(is_binary_file_by_extension(&path));
/// 
/// let path = PathBuf::from("example.txt");
/// assert!(!is_binary_file_by_extension(&path));
/// ```
pub fn is_binary_file_by_extension(path: &PathBuf) -> bool {
    if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
        BINARY_EXTENSIONS.contains(extension)
    } else {
        false
    }
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
pub fn is_likely_text_file(path: &PathBuf) -> Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0; 1024]; // 采样前 1KB 内容
    let n = file.read(&mut buffer)?;
    Ok(std::str::from_utf8(&buffer[..n]).is_ok() || is_likely_text_content(&buffer[..n]))
}

/// This function checks if the file content is likely text or not.
/// 
/// # Arguments
/// 
/// * `content` - A reference to a byte slice representing the file content.
/// 
/// # Returns
/// 
/// A boolean value indicating whether the file content is likely text or not
/// 
/// # Examples
/// 
/// ```
/// use minigrep::utils::is_likely_text_content;
/// 
/// let content = b"Hello, world!";
/// assert!(is_likely_text_content(content));
/// 
/// let content = b"\x00\x01\x02";
/// assert!(!is_likely_text_content(content));
/// ```
pub fn is_likely_text_content(content: &[u8]) -> bool {
    if content.is_empty() {
        return true;
    }
    // check for null bytes
    if content.contains(&0) {
        return true;
    }
    
    // check for printable characters ratio
    let printable_count = content.iter().filter(|&&byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace()).count();
    let ratio = printable_count as f64 / content.len() as f64;
    ratio > 0.95
}

/// Collects files from a given path, recursively if specified.
/// 
/// # Arguments
/// 
/// * `path` - The path to collect files from.
/// * `recursive` - Whether to collect files recursively.
/// * `max_file_size` - The maximum file size to collect.
/// * `files` - The vector to collect files into.
/// 
/// # Returns
/// 
/// A `Result` containing the collected files.
/// 
/// # Errors
/// 
/// Returns an error if the path is not a directory or if the directory cannot be read.
/// 
/// # Examples
/// 
/// ```
/// use std::path::PathBuf;
/// use minigrep::utils::collect_files;
/// 
/// let path = PathBuf::from("/path/to/directory");
/// let mut files = Vec::new();
/// collect_files(&path, true, 1024, &mut files).unwrap();
/// ```
pub fn collect_files(path: &PathBuf, recursive: bool, max_file_size: usize, files: &mut Vec<FileInfo>) -> Result<()> {
    if path.is_file(){
        if let Ok(info) = get_file_info(path, max_file_size) {
            files.push(info);
        }
    } else if path.is_dir() {
        let entrys = std::fs::read_dir(path).with_context(|| format!("Failed to read directory '{}'", path.display()))?;
        for entry in entrys {
            let entry = entry.with_context(|| format!("Failed to read entry '{}'", path.display()))?;
            let path = entry.path();
            if path.is_file() {
                if let Ok(info) = get_file_info(&path, max_file_size) {
                    files.push(info);
                }
            } else if path.is_dir() && recursive {
                collect_files(&path, recursive, max_file_size, files)?;
            } else {
                // Ignore other types of files, such as symlinks or devices
            }
        }
    }
    Ok(())
}


/// get file info and filter files based on size
/// 
/// filter file by extension and check if file size exceeds maximum allowed size
/// 
/// # Arguments
/// 
/// * `path` - The path to the file
/// * `max_file_size` - The maximum allowed file size in bytes
/// 
/// # Returns
/// 
/// A `Result` containing the file information or an error
/// 
/// # Errors
/// 
/// This function will return an error if the file cannot be read or if the regular expression is invalid.
/// 
/// # Examples
/// 
/// ```
/// use std::path::PathBuf;
/// use minigrep::get_file_info;
///
/// let path = PathBuf::from("example.txt");
/// let max_file_size = 1024;
/// let file_info = get_file_info(&path, max_file_size);
/// ```
fn get_file_info(path: &PathBuf, max_file_size: usize) -> Result<FileInfo> {
    // check if file is binary by extension
    if is_binary_file_by_extension(path) {
        return Err(anyhow::anyhow!("Binary file"))
    }
    
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to get metadata for file {}", path.display()))?;
    let size = metadata.len();
    
    // Check if file size exceeds maximum allowed size
    if size > max_file_size as u64 {
        return Err(anyhow::anyhow!("File size exceeds maximum allowed size"));
    }
    
    if is_likely_text_file(path).is_err() {
        return Err(anyhow::anyhow!("File is not likely a text file"));
    }
    
    Ok(FileInfo::new(path.clone(), size))
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
pub fn determine_capacity(path: &PathBuf) -> Result<usize> {
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
pub fn highlight_line(line: &str, re: &regex::Regex) -> String {
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



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_binary_file_by_extension() {
        let path = PathBuf::from("example.png");
        assert!(is_binary_file_by_extension(&path));

        let path = PathBuf::from("example");
        assert!(!is_binary_file_by_extension(&path));
    }
}