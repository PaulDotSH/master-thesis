# Description
Download crates.csv, depdendencies.csv and crate_downloads.csv from crates.io, and with that data we make a database containing the dependencies of each crate and info of all of the crates. After that we look for libraries with a similar name, then using a rule-based system, an LLM and code similarity analysis

# TODO:
- [ ] - Find an algorithm for similar name matching
- [ ] - Find an algorithm for code similarity (maybe append all files to one big file, remove main, and imports maybe derives and do duplicate line similarity? this wouldn't work for changed names though)
- [ ] - 

# CLI Features
- Build Database (using the csv files)
- Start analysis
