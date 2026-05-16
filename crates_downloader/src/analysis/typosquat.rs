//! Typosquatting detection algorithms
//!
//! This module implements various string similarity algorithms to detect
//! potential typosquatting attempts among crate names.

use std::collections::HashMap;

/// Result of typosquat analysis between two crate names
#[derive(Debug, Clone)]
pub struct TyposquatScore {
    pub levenshtein: u8,
    pub damerau_levenshtein: u8,
    pub jaro_winkler: u8,
    pub keyboard_distance: u8,
    pub prefix_similarity: u8,
    pub combined: u8,
}

impl TyposquatScore {
    /// Calculate combined score with weighted average
    pub fn calculate_combined(
        levenshtein: u8,
        damerau_levenshtein: u8,
        jaro_winkler: u8,
        keyboard_distance: u8,
        prefix_similarity: u8,
    ) -> u8 {
        // Weights for each algorithm (must sum to 100)
        const W_LEVENSHTEIN: u32 = 20;
        const W_DAMERAU: u32 = 25;
        const W_JARO_WINKLER: u32 = 25;
        const W_KEYBOARD: u32 = 15;
        const W_PREFIX: u32 = 15;

        let weighted_sum = (levenshtein as u32 * W_LEVENSHTEIN)
            + (damerau_levenshtein as u32 * W_DAMERAU)
            + (jaro_winkler as u32 * W_JARO_WINKLER)
            + (keyboard_distance as u32 * W_KEYBOARD)
            + (prefix_similarity as u32 * W_PREFIX);

        (weighted_sum / 100) as u8
    }
}

/// Calculate the Levenshtein distance between two strings
/// Returns the minimum number of single-character edits (insertions, deletions, substitutions)
pub fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let m = s1_chars.len();
    let n = s2_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    // Create two rows for the dynamic programming approach
    let mut prev_row: Vec<usize> = (0..=n).collect();
    let mut curr_row: Vec<usize> = vec![0; n + 1];

    for i in 1..=m {
        curr_row[0] = i;

        for j in 1..=n {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] {
                0
            } else {
                1
            };

            curr_row[j] = (prev_row[j] + 1) // deletion
                .min(curr_row[j - 1] + 1) // insertion
                .min(prev_row[j - 1] + cost); // substitution
        }

        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[n]
}

/// Convert Levenshtein distance to a similarity score (0-100)
/// Higher score means more similar
pub fn levenshtein_similarity(s1: &str, s2: &str) -> u8 {
    let distance = levenshtein_distance(s1, s2);
    let max_len = s1.len().max(s2.len());

    if max_len == 0 {
        return 100;
    }

    let similarity = 1.0 - (distance as f64 / max_len as f64);
    (similarity * 100.0).round() as u8
}

/// Calculate the Damerau-Levenshtein distance between two strings
/// Extends Levenshtein by also allowing transpositions of adjacent characters
pub fn damerau_levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let m = s1_chars.len();
    let n = s2_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    // Create a matrix for dynamic programming
    let mut d: Vec<Vec<usize>> = vec![vec![0; n + 1]; m + 1];

    for i in 0..=m {
        d[i][0] = i;
    }
    for j in 0..=n {
        d[0][j] = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] {
                0
            } else {
                1
            };

            d[i][j] = (d[i - 1][j] + 1) // deletion
                .min(d[i][j - 1] + 1) // insertion
                .min(d[i - 1][j - 1] + cost); // substitution

            // Transposition
            if i > 1
                && j > 1
                && s1_chars[i - 1] == s2_chars[j - 2]
                && s1_chars[i - 2] == s2_chars[j - 1]
            {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + cost);
            }
        }
    }

    d[m][n]
}

/// Convert Damerau-Levenshtein distance to a similarity score (0-100)
pub fn damerau_levenshtein_similarity(s1: &str, s2: &str) -> u8 {
    let distance = damerau_levenshtein_distance(s1, s2);
    let max_len = s1.len().max(s2.len());

    if max_len == 0 {
        return 100;
    }

    let similarity = 1.0 - (distance as f64 / max_len as f64);
    (similarity * 100.0).round() as u8
}

/// Calculate the Jaro similarity between two strings
fn jaro_similarity(s1: &str, s2: &str) -> f64 {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let m = s1_chars.len();
    let n = s2_chars.len();

    if m == 0 && n == 0 {
        return 1.0;
    }
    if m == 0 || n == 0 {
        return 0.0;
    }

    let match_distance = (m.max(n) / 2).saturating_sub(1);

    let mut s1_matches = vec![false; m];
    let mut s2_matches = vec![false; n];
    let mut matches = 0;
    let mut transpositions = 0;

    // Find matches
    for i in 0..m {
        let start = i.saturating_sub(match_distance);
        let end = (i + match_distance + 1).min(n);

        for j in start..end {
            if s2_matches[j] || s1_chars[i] != s2_chars[j] {
                continue;
            }
            s1_matches[i] = true;
            s2_matches[j] = true;
            matches += 1;
            break;
        }
    }

    if matches == 0 {
        return 0.0;
    }

    // Count transpositions
    let mut k = 0;
    for i in 0..m {
        if !s1_matches[i] {
            continue;
        }
        while !s2_matches[k] {
            k += 1;
        }
        if s1_chars[i] != s2_chars[k] {
            transpositions += 1;
        }
        k += 1;
    }

    let matches = matches as f64;
    let transpositions = transpositions as f64 / 2.0;

    (matches / m as f64 + matches / n as f64 + (matches - transpositions) / matches) / 3.0
}

/// Calculate the Jaro-Winkler similarity between two strings
/// Gives more favorable ratings to strings that match from the beginning
pub fn jaro_winkler_similarity(s1: &str, s2: &str) -> u8 {
    let jaro = jaro_similarity(s1, s2);

    // Calculate common prefix length (up to 4 characters)
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let prefix_len = s1_chars
        .iter()
        .zip(s2_chars.iter())
        .take(4)
        .take_while(|(a, b)| a == b)
        .count();

    // Winkler modification: p = 0.1 (standard scaling factor)
    let jaro_winkler = jaro + (prefix_len as f64 * 0.1 * (1.0 - jaro));

    (jaro_winkler * 100.0).round().min(100.0) as u8
}

/// QWERTY keyboard layout for distance calculations
fn get_keyboard_layout() -> HashMap<char, (f64, f64)> {
    let mut layout = HashMap::new();

    // Row 0 (numbers)
    let row0 = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-'];
    for (i, c) in row0.iter().enumerate() {
        layout.insert(*c, (i as f64, 0.0));
    }

    // Row 1
    let row1 = ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'];
    for (i, c) in row1.iter().enumerate() {
        layout.insert(*c, (i as f64 + 0.25, 1.0));
    }

    // Row 2
    let row2 = ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'];
    for (i, c) in row2.iter().enumerate() {
        layout.insert(*c, (i as f64 + 0.5, 2.0));
    }

    // Row 3
    let row3 = ['z', 'x', 'c', 'v', 'b', 'n', 'm'];
    for (i, c) in row3.iter().enumerate() {
        layout.insert(*c, (i as f64 + 0.75, 3.0));
    }

    // Special characters common in crate names
    layout.insert('_', (10.5, 0.0)); // Near hyphen

    layout
}

/// Calculate keyboard distance between two characters
fn char_keyboard_distance(c1: char, c2: char, layout: &HashMap<char, (f64, f64)>) -> f64 {
    let c1_lower = c1.to_ascii_lowercase();
    let c2_lower = c2.to_ascii_lowercase();

    match (layout.get(&c1_lower), layout.get(&c2_lower)) {
        (Some((x1, y1)), Some((x2, y2))) => ((x2 - x1).powi(2) + (y2 - y1).powi(2)).sqrt(),
        _ => 5.0, // Default distance for unknown characters
    }
}

/// Calculate keyboard-based similarity score
/// Considers that typos often involve adjacent keys on the keyboard
pub fn keyboard_distance_similarity(s1: &str, s2: &str) -> u8 {
    let layout = get_keyboard_layout();
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();

    if s1_chars.len() != s2_chars.len() {
        // Length mismatch - use weighted combination with length similarity
        let len_diff = (s1_chars.len() as i32 - s2_chars.len() as i32).abs();
        let max_len = s1_chars.len().max(s2_chars.len());
        let len_similarity = 1.0 - (len_diff as f64 / max_len as f64);

        // For strings of different lengths, compare common prefix and suffix
        let min_len = s1_chars.len().min(s2_chars.len());
        let mut total_distance = 0.0;

        for i in 0..min_len {
            if s1_chars[i] != s2_chars[i] {
                total_distance += char_keyboard_distance(s1_chars[i], s2_chars[i], &layout);
            }
        }

        // Add penalty for extra characters
        total_distance += len_diff as f64 * 2.0;

        let max_possible_distance = max_len as f64 * 5.0;
        let char_similarity = 1.0 - (total_distance / max_possible_distance);

        return ((char_similarity * 0.7 + len_similarity * 0.3) * 100.0).round().clamp(0.0, 100.0) as u8;
    }

    // Same length - compare character by character
    let mut total_distance = 0.0;
    let mut differences = 0;

    for (c1, c2) in s1_chars.iter().zip(s2_chars.iter()) {
        if c1 != c2 {
            differences += 1;
            total_distance += char_keyboard_distance(*c1, *c2, &layout);
        }
    }

    if differences == 0 {
        return 100;
    }

    // Max distance per character is roughly 5 (diagonal across keyboard)
    let max_distance = differences as f64 * 5.0;
    let similarity = 1.0 - (total_distance / max_distance);

    // Weight by number of different characters
    let diff_penalty = 1.0 - (differences as f64 / s1_chars.len() as f64);
    let final_similarity = similarity * 0.5 + diff_penalty * 0.5;

    (final_similarity * 100.0).round().min(100.0) as u8
}

/// Calculate prefix similarity
/// Important for detecting typosquats that share the same prefix
pub fn prefix_similarity(s1: &str, s2: &str) -> u8 {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();

    let common_prefix_len = s1_chars
        .iter()
        .zip(s2_chars.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let max_len = s1_chars.len().max(s2_chars.len());
    if max_len == 0 {
        return 100;
    }

    // Give extra weight to longer common prefixes
    let prefix_ratio = common_prefix_len as f64 / max_len as f64;

    // Bonus for prefixes that are at least 3 characters
    let bonus = if common_prefix_len >= 3 { 0.1 } else { 0.0 };

    ((prefix_ratio + bonus) * 100.0).round().min(100.0) as u8
}

/// Calculate all similarity scores between two crate names
pub fn calculate_all_scores(name1: &str, name2: &str) -> TyposquatScore {
    let levenshtein = levenshtein_similarity(name1, name2);
    let damerau_levenshtein = damerau_levenshtein_similarity(name1, name2);
    let jaro_winkler = jaro_winkler_similarity(name1, name2);
    let keyboard_distance = keyboard_distance_similarity(name1, name2);
    let prefix_sim = prefix_similarity(name1, name2);

    let combined = TyposquatScore::calculate_combined(
        levenshtein,
        damerau_levenshtein,
        jaro_winkler,
        keyboard_distance,
        prefix_sim,
    );

    TyposquatScore {
        levenshtein,
        damerau_levenshtein,
        jaro_winkler,
        keyboard_distance,
        prefix_similarity: prefix_sim,
        combined,
    }
}

/// Check if two names might be typosquats of each other
/// Returns Some(score) if they're similar enough, None otherwise
pub fn check_typosquat(name1: &str, name2: &str, min_combined_score: u8) -> Option<TyposquatScore> {
    // Quick length check - if length difference is too great, skip expensive calculations
    let len_diff = (name1.len() as i32 - name2.len() as i32).abs();
    let max_len = name1.len().max(name2.len());

    // If length difference is more than 30% of max length, probably not a typosquat
    if max_len > 0 && len_diff as f64 / max_len as f64 > 0.3 {
        return None;
    }

    // Skip if names are identical
    if name1 == name2 {
        return None;
    }

    let scores = calculate_all_scores(name1, name2);

    if scores.combined >= min_combined_score {
        Some(scores)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", ""), 3);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("serde", "serde"), 0);
        assert_eq!(levenshtein_distance("serde", "serge"), 1);
    }

    #[test]
    fn test_damerau_levenshtein_distance() {
        // Transposition should be 1, not 2
        assert_eq!(damerau_levenshtein_distance("ab", "ba"), 1);
        assert_eq!(damerau_levenshtein_distance("abc", "acb"), 1);
    }

    #[test]
    fn test_jaro_winkler() {
        let score = jaro_winkler_similarity("serde", "serde");
        assert_eq!(score, 100);

        let score = jaro_winkler_similarity("serde", "serge");
        assert!(score > 80);
    }

    #[test]
    fn test_prefix_similarity() {
        assert_eq!(prefix_similarity("tokio", "tokio-rs"), 62); // 5/8 + bonus
        assert_eq!(prefix_similarity("rand", "random"), 67); // 4/6 + bonus
    }

    #[test]
    fn test_typosquat_detection() {
        // These should be detected as potential typosquats
        let score = check_typosquat("serde", "serge", 70);
        assert!(score.is_some());

        let score = check_typosquat("tokio", "tokoi", 70);
        assert!(score.is_some());

        // These should not
        let score = check_typosquat("serde", "tokio", 70);
        assert!(score.is_none());
    }
}
