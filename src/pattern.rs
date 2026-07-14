//! Glob-style pattern matching for command rules.
//!
//! Only `*` is special: it matches any sequence of characters, including
//! spaces. Matching is case-sensitive and anchored at both ends, so the
//! pattern `git status*` matches `git status` and `git status --short`,
//! but not `xgit status`.

/// Returns true if `text` matches `pattern`.
///
/// Implemented with the classic two-pointer wildcard algorithm: linear in
/// the input sizes, no backtracking blowup, no regex dependency.
pub fn matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position of the last `*` seen in the pattern, and the text position
    // that star is currently assumed to cover up to.
    let mut star: Option<usize> = None;
    let mut mark = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last star absorb one more character.
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    // Any trailing stars match the empty string.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Returns the first pattern in `patterns` that matches `text`, if any.
pub fn first_match<'a>(patterns: &'a [String], text: &str) -> Option<&'a str> {
    patterns
        .iter()
        .find(|p| matches(p, text))
        .map(|p| p.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(matches("pwd", "pwd"));
        assert!(!matches("pwd", "pwdx"));
        assert!(!matches("pwd", "xpwd"));
    }

    #[test]
    fn trailing_star() {
        assert!(matches("git status*", "git status"));
        assert!(matches("git status*", "git status --short"));
        assert!(!matches("git status*", "git stash"));
    }

    #[test]
    fn star_matches_spaces() {
        assert!(matches("cat *", "cat /etc/hosts and more"));
        assert!(!matches("cat *", "cat"));
    }

    #[test]
    fn leading_and_middle_star() {
        assert!(matches("*apply*", "kubectl apply -f x.yaml"));
        assert!(matches("git * --force", "git push origin --force"));
        assert!(!matches(
            "git * --force",
            "git push origin --force-with-lease"
        ));
    }

    #[test]
    fn multiple_stars() {
        assert!(matches("a*b*c", "a-x-b-y-c"));
        assert!(!matches("a*b*c", "a-x-b-y"));
    }

    #[test]
    fn star_only_and_empty() {
        assert!(matches("*", ""));
        assert!(matches("*", "anything at all"));
        assert!(matches("", ""));
        assert!(!matches("", "x"));
    }

    #[test]
    fn case_sensitive() {
        assert!(!matches("ls*", "LS -la"));
    }

    #[test]
    fn unicode_text() {
        assert!(matches("echo *", "echo こんにちは"));
    }

    #[test]
    fn first_match_returns_first() {
        let pats = vec!["rm *".to_string(), "rm -rf *".to_string()];
        assert_eq!(first_match(&pats, "rm -rf /tmp/x"), Some("rm *"));
        assert_eq!(first_match(&pats, "ls"), None);
    }
}
