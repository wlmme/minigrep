use clap::Parser;

/// Configuration for the grep tool.
///
/// This struct represents the configuration options(Cli args) for the grep tool.
#[derive(Parser, Debug)]
#[command(
    about = "A simple grep tool",
    long_about = "A simple grep tool used to search for matching text in files, supports regular expressions, supports multi-threaded parallel search, supports recursive search."
)]
pub struct Config {
    /// Ignore case, default enabled
    #[arg(short = 'i', long, help = "Ignore case", action = clap::ArgAction::SetTrue)]
    pub ignore_case: bool,

    /// Recursive search, default disabled
    #[arg(short = 'r', long, help = "Recursive search", action = clap::ArgAction::SetTrue)]
    pub recursive: bool,
    
    /// Number of threads to use for parallel search, default is 1
    #[arg(short = 't', long, help = "Number of threads to use for parallel search", default_value_t = 1)]
    pub threads: usize,
    
    /// Maximum file size in MB, default is unlimited
    #[arg(short = 's', long, help = "Maximum file size in MB, default is unlimited", default_value_t = usize::MAX)]
    pub max_file_size: usize,

    /// Matching expression
    #[arg(help = "Matching expression")]
    pub pattern: String,

    /// Multiple paths separated by spaces, default is to search the current directory
    #[arg(help = "Multiple paths separated by spaces, default is to search the current directory")]
    pub path: Option<Vec<String>>,
}
