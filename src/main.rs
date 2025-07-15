use anyhow::{Result};
use clap::Parser;
use minigrep::{greps, Config};

/// Main function
/// 
/// This function is the entry point of the program. It parses the command-line arguments,
/// initializes the configuration, and starts the search process.
fn main() -> Result<()> {
    // get the config (cli app arguments)
    let config = Config::parse();

    // search prompt
    print!("Searching {:?} in paths: {}",
        config.pattern,
        if config.path.is_none() || config.path.clone().unwrap().is_empty() {
            "[CURRENT DIRECTORY]".to_string()
        } else {
            format!("{:?}", config.path.clone().unwrap())
        }
    );
    let rules_enabled = config.ignore_case || config.recursive;
    let rules_enabled_str = if rules_enabled {
        format!(" withing the rules:\n - {}\n - {}\n",
           if config.ignore_case { "ignore case" } else { "case sensitive" },
           if config.recursive { "recursive" } else { "non-recursive" })
    } else {
        "".to_string()
    };
    println!("{}", rules_enabled_str);
    
    // call grep function in lib.rs
    greps(&config)?;

    Ok(())
}
