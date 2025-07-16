mod args;
mod error;
mod utils;

use std::{
    fs::File,
    io::BufReader,
    path::PathBuf,
};

use anyhow::{Context, Ok, Result};
pub use args::Config;
pub use error::GrepError;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::io::BufRead;

/// Represents information about a file.
/// 
/// This struct contains the path to the file and its size.
#[derive(Debug, Clone)]
struct FileInfo {
    /// Path to the file.
    path: PathBuf,
    /// Size of the file in bytes.
    size: u64,
}

impl FileInfo {
    /// Creates a new `FileInfo` instance.
    fn new(path: PathBuf, size: u64) -> Self {
        Self { path, size }
    }
}

/// Represents the result of a search.
/// 
/// This struct contains the path to the file, the line number, and the line itself.
#[derive(Debug, Clone)]
struct SearchResult {
    /// Path to the file.
    path: PathBuf,
    /// Line number in the file.
    line_number: u64,
    /// Line content.
    line: String,
}

impl SearchResult {
    /// Creates a new `SearchResult` instance.
    fn new(path: PathBuf, line_number: u64, line: String) -> Self {
        Self {
            path,
            line_number,
            line,
        }
    }
}

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
    let thread_count = if config.threads == 0 {
        num_cpus::get()
    } else {
        config.threads
    };
    let max_file_size = config.max_file_size;
    
    // println!("Initializing parallel...");
    // setting rayon thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global()
        .context("Failed to initialize thread pool")?;

    // println!("Assembling pattern...")
    // convert pattern to regex
    let regex_pattern = regex::RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .context("Pattern is invalid")?;
    
    // println!("Collecting files...");
    let mut files = Vec::new();
    // if path is None then search current directory else search in the given path
    if path.is_none() || path.unwrap().is_empty() {
        let current_dir = std::env::current_dir().context("failed to get current directory")?;
        let path = PathBuf::from(current_dir);
        utils::collect_files(&path, recursive, max_file_size, &mut files)?;
    } else {
        let paths: Vec<PathBuf> = path.unwrap()
            .iter()
            .map(|s| -> PathBuf { PathBuf::from(s) })
            .collect();
        for path in paths {
            utils::collect_files(&path, recursive, max_file_size, &mut files)?;
        }
    }
    
    // if no files are found then print message and return
    if files.is_empty() {
        println!("No files found to search.");
        return Ok(());
    }
    
    // parallel searching files
    let results: Vec<SearchResult> = files.par_iter()
        .filter_map(|file_info| {
            search_file_parallel(&regex_pattern, file_info).ok()
        })
        .flatten()
        .collect();

    // sort results by file path and line number
    let mut sorted_results = results;
    sorted_results.sort_by(|a, b| {
        a.path.cmp(&b.path).then(a.line_number.cmp(&b.line_number))
    });

    // print results
    for result in sorted_results {
        println!("{}:\x1b[41;31m[{}]\x1b[0m:{}", result.path.display(), result.line_number, result.line);
    }

    Ok(())
}

/// Search a file in parallel using multiple threads.
/// 
/// This function uses the `rayon` crate to parallelize the search operation.
/// 
/// # Arguments
/// 
/// * `re` - The regular expression pattern to search for.
/// * `file_info` - The file information to search.
/// * `max_file_size` - The maximum file size to search.
/// 
/// # Returns
/// 
/// A `Result` containing a vector of search results.
/// 
/// # Errors
/// 
/// Returns an error if the file cannot be opened or read.
/// 
/// #Examples
/// 
/// ```
/// use minigrep::search_file_parallel;
/// use regex::Regex;
/// use std::fs::File;
/// use std::path::Path;
/// 
/// let regex_pattern = Regex::new(r"hello").unwrap();
/// let file_info = FileInfo::new(File::open(Path::new("example.txt")).unwrap(), 1024);
/// let max_file_size = 1024 * 1024;
/// 
/// let results = search_file_parallel(&regex_pattern, &file_info, max_file_size);
/// assert!(results.is_ok());
/// ```
fn search_file_parallel(re: &regex::Regex, file_info: &FileInfo) -> Result<Vec<SearchResult>>{
    let mut results = Vec::new();
    if file_info.size > 1024 * 1024 {
        search_file_with_mmap(re, file_info, &mut results)?;
    } else {
        search_file_buffered(re, file_info, &mut results)?;
    }
    Ok(results)
}


/// Search file using buffered reader
/// 
/// This function searches a file using a buffered reader and returns a vector of search results.
/// 
/// # Arguments
/// 
/// * `re` - A reference to a regular expression used for searching.
/// * `file_info` - A reference to a `FileInfo` struct containing information about the file.
/// * `results` - A mutable reference to a vector of `SearchResult` structs where the search results will be stored.
/// 
/// # Returns
/// 
/// A `Result` indicating success or failure.
/// 
/// # Errors
/// 
/// This function will return an error if:
/// * The file cannot be opened.
/// * The file size cannot be determined.
/// * The file cannot be read.
/// * The file cannot be closed.
/// 
/// # Examples
/// 
/// ```
/// use minigrep::search_file_buffered;
/// use minigrep::FileInfo;
/// use minigrep::SearchResult;
/// 
/// let re = regex::Regex::new(r"hello").unwrap();
/// let file_info = FileInfo::new("path/to/file.txt");
/// let mut results = Vec::new();
/// 
/// search_file_buffered(&re, &file_info, &mut results).unwrap();
/// assert_eq!(results.len(), 1);
/// ```
fn search_file_buffered(re: &regex::Regex, file_info: &FileInfo, results: &mut Vec<SearchResult>) -> Result<()> {
    let file = File::open(&file_info.path)
        .with_context(|| format!("Failed to open file {}", file_info.path.display()))?;
    let capacity = utils::determine_capacity(&file_info.path)?;
    let reader = BufReader::with_capacity(capacity, file);
    for (line_number, line) in reader.lines().enumerate() {
        let line = line.with_context( || format!("Failed to read line #{} in file {}", line_number + 1, file_info.path.display()))?;
        if re.is_match(&line) {
            results.push(SearchResult::new(file_info.path.clone(), (line_number + 1) as u64, utils::highlight_line(&line, re)));
        }
    }
    Ok(())
}

fn search_file_with_mmap(re: &regex::Regex, file_info: &FileInfo, results: &mut Vec<SearchResult>) -> Result<()> {
    let file = File::open(&file_info.path)
        .with_context(|| format!("Failed to open file {}", file_info.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("Failed to map file {}", file_info.path.display()))?;
    // check if the file is likely to be text content
    if !utils::is_likely_text_content(&mmap[..std::cmp::min(512, mmap.len())]) {
        return Ok(());
    }
    let content = String::from_utf8_lossy(&mmap);
    for (line_number, line) in content.lines().enumerate() {
        if re.is_match(line) {
            results.push(SearchResult::new(file_info.path.clone(), (line_number + 1) as u64, utils::highlight_line(line, re)));
        }
    }
    Ok(())
}

