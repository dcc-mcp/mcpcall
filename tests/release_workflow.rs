//! Dependency-free checks for the release authentication contract. Actionlint
//! validates YAML; these checks deliberately target the release-please job.

use std::sync::LazyLock;

static WORKFLOW: LazyLock<String> =
    LazyLock::new(|| normalize_workflow(include_str!("../.github/workflows/release.yml")));
const TOKEN: &str = "${{ secrets.PERSONAL_ACCESS_TOKEN }}";

fn normalize_workflow(workflow: &str) -> String {
    workflow.replace("\r\n", "\n")
}

fn release_steps(workflow: &str) -> Vec<&str> {
    let job = workflow
        .split_once("  release-please:\n")
        .expect("release-please job must exist")
        .1
        .split("\n  build-binaries:")
        .next()
        .unwrap();
    job.split("\n      - ").skip(1).collect()
}

fn check_authentication(workflow: &str) -> Result<(), &'static str> {
    let steps = release_steps(workflow);
    let action_index = steps
        .iter()
        .position(|step| step.starts_with("uses: googleapis/release-please-action@v5\n"))
        .ok_or("release-please action must retain its version")?;
    let action = steps[action_index];
    let token_line = format!("          token: {TOKEN}");
    if !action.lines().any(|line| line == token_line) {
        return Err("release-please must use the explicit PAT without a fallback");
    }
    let preflight = action_index
        .checked_sub(1)
        .map(|index| steps[index])
        .ok_or("token preflight must immediately precede release-please")?;
    if !preflight.starts_with("name: Require release token\n")
        || !preflight.contains("\n        shell: bash\n")
        || !preflight.contains(&format!("\n          RELEASE_PLEASE_TOKEN: {TOKEN}\n"))
        || !preflight.contains("\n        run: |\n")
    {
        return Err("token preflight must check the same explicit PAT");
    }
    for step in [preflight, action] {
        if step.lines().any(|line| {
            line.starts_with("        if:") || line.starts_with("        continue-on-error:")
        }) {
            return Err("release authentication must not be conditional or allowed to fail");
        }
    }
    Ok(())
}

#[test]
fn release_please_requires_the_explicit_token() {
    check_authentication(&WORKFLOW).unwrap();
    let steps = release_steps(&WORKFLOW);
    let action = steps.last().unwrap();
    for expected in [
        "        id: release\n",
        "          config-file: release-please-config.json\n",
        "          manifest-file: .release-please-manifest.json",
    ] {
        assert!(
            action.contains(expected),
            "missing release setting: {expected}"
        );
    }
    assert!(WORKFLOW.contains("release_created: ${{ steps.release.outputs.release_created }}"));
    assert!(WORKFLOW.contains("tag_name: ${{ steps.release.outputs.tag_name }}"));
}

#[test]
fn crlf_workflow_preserves_parsing_and_authentication_negative_controls() {
    let lf = normalize_workflow(include_str!("../.github/workflows/release.yml"));
    let crlf = lf.replace('\n', "\r\n");
    assert!(crlf.contains("\r\n"));
    let normalized = normalize_workflow(&crlf);
    assert_eq!(release_steps(&normalized), release_steps(&lf));
    check_authentication(&normalized).unwrap();

    let missing_guard = normalized.replacen("      - name: Require release token\n", "", 1);
    assert!(check_authentication(&missing_guard).is_err());
    let skippable = normalized.replacen(
        "name: Require release token\n",
        "name: Require release token\n        if: false\n",
        1,
    );
    assert!(check_authentication(&skippable).is_err());
    let fallback = normalized.replace(
        &format!("token: {TOKEN}"),
        "token: ${{ secrets.PERSONAL_ACCESS_TOKEN || github.token }}",
    );
    assert!(check_authentication(&fallback).is_err());
}

#[test]
fn rejects_implicit_token_fallbacks() {
    for fallback in ["github.token", "secrets.GITHUB_TOKEN"] {
        let mutated = WORKFLOW.replace(
            &format!("token: {TOKEN}"),
            &format!("token: ${{{{ secrets.PERSONAL_ACCESS_TOKEN || {fallback} }}}}"),
        );
        assert!(check_authentication(&mutated).is_err());
    }
}

#[test]
fn rejects_missing_or_late_preflight() {
    let steps = release_steps(&WORKFLOW);
    let preflight = format!("      - {}", steps[0]);
    let without_preflight = WORKFLOW.replacen(&preflight, "", 1);
    assert!(check_authentication(&without_preflight).is_err());

    let late_preflight = without_preflight.replace(
        "\n  build-binaries:",
        &format!("\n{preflight}\n  build-binaries:"),
    );
    assert!(check_authentication(&late_preflight).is_err());
}

#[test]
fn rejects_skippable_authentication() {
    for name in [
        "name: Require release token\n",
        "uses: googleapis/release-please-action@v5\n",
    ] {
        for setting in ["if: false", "continue-on-error: true"] {
            let mutated = WORKFLOW.replacen(name, &format!("{name}        {setting}\n"), 1);
            assert!(check_authentication(&mutated).is_err());
        }
    }
}

#[test]
fn rejects_wrong_preflight_token() {
    let mutated = WORKFLOW.replace(
        &format!("RELEASE_PLEASE_TOKEN: {TOKEN}"),
        "RELEASE_PLEASE_TOKEN: ${{ github.token }}",
    );
    assert!(check_authentication(&mutated).is_err());
}

// The release job runs on Ubuntu. Keep shell execution portable for the rest
// of the workspace's Windows CI matrix; its structural checks above still run.
#[cfg(unix)]
fn run_preflight(token: Option<&str>) -> std::process::Output {
    let steps = release_steps(&WORKFLOW);
    let script = steps[0]
        .split_once("\n        run: |\n")
        .unwrap()
        .1
        .lines()
        .map(|line| line.strip_prefix("          ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    let mut command = std::process::Command::new("bash");
    command
        .args([
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            &script,
        ])
        .env_remove("BASH_ENV")
        .env_remove("RELEASE_PLEASE_TOKEN")
        .env("GITHUB_TOKEN", "synthetic-implicit-token");
    if let Some(token) = token {
        command.env("RELEASE_PLEASE_TOKEN", token);
    }
    command.output().expect("bash is required on Unix")
}

#[cfg(unix)]
#[test]
fn preflight_fails_closed_for_unset_and_empty_tokens() {
    for token in [None, Some("")] {
        let output = run_preflight(token);
        assert!(
            !output.status.success(),
            "missing PAT must stop release-please"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("::error::PERSONAL_ACCESS_TOKEN is required"));
        assert!(!stderr.contains("synthetic-implicit-token"));
    }
}

#[cfg(unix)]
#[test]
fn preflight_accepts_a_nonempty_token_without_logging_it() {
    let output = run_preflight(Some("synthetic-pat-$-quoted-'\""));
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
