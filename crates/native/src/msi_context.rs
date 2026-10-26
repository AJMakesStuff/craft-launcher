//! MSI update context is authoritative, not inferred from a display registry entry.
//! An existing copy must never fall back to a fresh installation when discovery fails.

use crate::install::MsiScope;

const UNKNOWN_CONTEXT: &str = "Windows could not confirm who this app is installed for. No changes were made. Try the app's installer instead.";

pub(crate) fn update_scope(
    is_msi: bool,
    product_code: Option<&str>,
    probe: impl FnOnce(&str) -> Result<MsiScope, String>,
) -> Result<Option<MsiScope>, String> {
    if !is_msi {
        return Ok(None);
    }
    let code = product_code.filter(|code| valid_product_code(code)).ok_or(UNKNOWN_CONTEXT)?;
    probe(code).map(Some)
}

pub(crate) fn valid_product_code(code: &str) -> bool {
    code.len() == 38
        && code.bytes().enumerate().all(|(index, byte)| match index {
            0 => byte == b'{',
            37 => byte == b'}',
            9 | 14 | 19 | 24 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn parse_contexts(output: &str) -> Result<MsiScope, String> {
    let mut scope = None;
    for line in output.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let context = match line {
            "1" | "2" => MsiScope::PerUser,
            "4" => MsiScope::PerMachine,
            _ => return Err(UNKNOWN_CONTEXT.into()),
        };
        if scope.is_some_and(|previous| previous != context) {
            return Err("This app is installed for both your account and everyone. Use its installer to choose which copy to update.".into());
        }
        scope = Some(context);
    }
    scope.ok_or_else(|| UNKNOWN_CONTEXT.into())
}

#[cfg(windows)]
pub(crate) fn probe(product_code: &str) -> Result<MsiScope, String> {
    use std::path::PathBuf;
    use std::time::Duration;

    if !valid_product_code(product_code) {
        return Err(UNKNOWN_CONTEXT.into());
    }
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).filter(|root| root.is_absolute()).ok_or(UNKNOWN_CONTEXT)?;
    let powershell = root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    // Only a validated GUID is interpolated. ProductsEx reads registration for the current
    // account and the machine, never another account and never Win32_Product (which repairs).
    let script = format!("$code='{product_code}';\n{}", include_str!("msi_context.ps1"));
    let mut command = crate::process::command(powershell);
    command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    let output =
        crate::process::run_command(command, "Windows installation lookup", Duration::from_secs(10)).map_err(|_| UNKNOWN_CONTEXT.to_string())?;
    parse_contexts(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "{12345678-1234-1234-1234-123456789ABC}";

    #[test]
    fn authoritative_machine_context_is_preserved() {
        assert_eq!(parse_contexts("4\r\n"), Ok(MsiScope::PerMachine));
    }

    #[test]
    fn managed_and_unmanaged_accounts_are_both_per_user() {
        assert_eq!(parse_contexts("1\n"), Ok(MsiScope::PerUser));
        assert_eq!(parse_contexts("2\n"), Ok(MsiScope::PerUser));
        assert_eq!(parse_contexts("1\n2\n"), Ok(MsiScope::PerUser));
    }

    #[test]
    fn missing_unknown_or_conflicting_contexts_are_not_guessed() {
        for output in ["", " \r\n", "0", "7", "user", "2\n4", "4\n1", "4\nnoise"] {
            assert!(parse_contexts(output).is_err(), "{output:?}");
        }
    }

    #[test]
    fn fresh_installs_do_not_probe_or_override_the_package_default() {
        assert_eq!(update_scope(false, None, |_| Err("must not probe".into())), Ok(None));
    }

    #[test]
    fn known_updates_keep_the_authoritative_context() {
        for scope in [MsiScope::PerUser, MsiScope::PerMachine] {
            assert_eq!(update_scope(true, Some(CODE), |_| Ok(scope)), Ok(Some(scope)));
        }
    }

    #[test]
    fn an_update_without_its_product_code_stops_before_probing() {
        let called = std::cell::Cell::new(false);
        assert!(
            update_scope(true, None, |_| {
                called.set(true);
                Ok(MsiScope::PerMachine)
            })
            .is_err()
        );
        assert!(!called.get());
    }

    #[test]
    fn malformed_product_codes_stop_before_any_shell_call() {
        for code in ["", "not-a-guid", "{12345678-1234-1234-1234-123456789ABZ}", "';exit 0;#", "{12345678-1234-1234-1234-123456789ABC}\n"] {
            let called = std::cell::Cell::new(false);
            assert!(
                update_scope(true, Some(code), |_| {
                    called.set(true);
                    Ok(MsiScope::PerMachine)
                })
                .is_err()
            );
            assert!(!called.get(), "{code:?}");
        }
    }

    #[test]
    fn unavailable_context_never_becomes_a_fresh_install() {
        assert!(update_scope(true, Some(CODE), |_| Err("query failed".into())).is_err());
    }
}
