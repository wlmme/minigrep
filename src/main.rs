
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(about = "A simple grep tool", long_about = "A simple grep tool used to search for matching text in files, supports regular expressions, supports multi-threaded parallel search, supports recursive search.")]
struct Config {
    /// Ignore case, default enabled
    #[arg(short = 'i', long, help = "Ignore case", action = clap::ArgAction::SetTrue)]
    ignore_case: bool,
    
    /// Multi-threaded parallel search, default disabled
    #[arg(short = 'p', long, help = "Multi-threaded parallel search", action = clap::ArgAction::SetTrue)]
    parallel: bool,
    
    /// Recursive search, default disabled
    #[arg(short = 'r', long, help = "Recursive search", action = clap::ArgAction::SetTrue)]
    recursive: bool,
    
    /// Matching expression
    #[arg(help = "Matching expression")]
    pattern: String,
    
    /// Multiple paths separated by spaces, default is to search the current directory
    #[arg(help = "Multiple paths separated by spaces, default is to search the current directory")]
    path: Option<Vec<String>>,
}

fn main() -> Result<()> {
    // get the config (cli app arguments)
    let config = Config::parse();

    print!("Searching {:?} in paths: {}",
        config.pattern,
        if config.path.is_none() || config.path.clone().unwrap().is_empty() {
            "[CURRENT DIRECTORY]".to_string()
        } else {
            format!("{:?}", config.path.unwrap())
        }
    );
    let rules_enabled = config.ignore_case || config.recursive || config.parallel;
    let rules_enabled_str = if rules_enabled {
        format!(" under the rules:\n - {}\n - {}\n - {}\n",
           if config.ignore_case { "ignore case" } else { "case sensitive" },
           if config.recursive { "recursive" } else { "non-recursive" },
           if config.parallel { "parallel" } else { "sequential" })
    } else {
        "".to_string()
    };
    println!("{}", rules_enabled_str);
    
    Ok(())
}
