use crate::role_utils::{CommonConfiguration, Role};
use product_config::types::PropertyNameKind;
use product_config::PropertyValidationResult;
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, error, warn};

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid configuration found")]
    InvalidConfiguration,
}

///
/// Given the configuration parameters of all `roles` partition them by `PropertyNameKind` and
/// merge them with the role groups configuration parameters.
///
/// The output is a map keyed by the role names. The value is also a map keyed by role group names and
/// the values are the merged configuration properties "bucketed" by `PropertyNameKind`.
/// # Arguments
/// - `resource`         - Not used directly. It's passed on to the `Configuration::compute_*` calls.
/// - `role_information` - A map keyed by role names. The value is a vector of `PropertyNameKind`
/// - `roles`            - A map keyed by role names.
///
pub fn transform_all_roles_to_config<T>(
    resource: &T::Configurable,
    role_information: HashMap<String, Vec<PropertyNameKind>>,
    roles: HashMap<String, Role<T>>,
) -> RoleConfigByPropertyKind
where
    T: Configuration,
{
    let mut result = HashMap::new();

    for (role_name, role) in roles {
        let role_properties = transform_role_to_config(
            resource,
            &role_name,
            &role,
            // TODO: What to do when role_name not in role_information
            role_information.get(&role_name).unwrap(),
        );
        result.insert(role_name, role_properties);
    }

    result
}

/// Given a single `role`, it generates a data structure suitable for applying a
/// product configuration.
/// The configuration objects of the role groups contained in the given `role` are
/// merged with that of the `role` it's self.
/// In addition, the `*_overrides` settings are also merged in the resulting configuration
/// with the highest priority.
/// The merge priority chain looks like this:
///
/// group overrides -> group config -> role overrides -> role config
///
/// where '->' means "overwrites if existing or adds".
///
/// The output is a map with one entry, keyed by `role_name` and the value is a map where all
/// configuration properties defined in the `role` are partitioned by `PropertyNameKind`.
/// # Arguments
/// - `resource`       - Not used directly. It's passed on to the `Configuration::compute_*` calls.
/// - `role_name`      - Used as key in the output and to partition the configuration properties.
/// - `role`           - The role for which to transform the configuration parameters.
///
fn transform_role_to_config<T>(
    resource: &T::Configurable,
    role_name: &str,
    role: &Role<T>,
) -> HashMap<String, UserConfigAndOverrides>
where
    T: Configuration,
{
    let mut result = HashMap::new();

    let role_properties =
        partition_properties_by_kind(resource, role_name, &role.config, property_kinds);

    // for each role group ...
    for (role_group_name, role_group) in &role.role_groups {
        // ... compute the group properties ...
        let role_group_properties = partition_properties_by_kind(
            resource,
            role_group_name,
            &role_group.config,
            property_kinds,
        );

        // ... and merge them with the role properties.
        let mut role_properties_copy = role_properties.clone();
        for (property_kind, properties) in role_group_properties {
            role_properties_copy
                .entry(property_kind)
                .or_default()
                .extend(properties);
        }

        result.insert(role_group_name.clone(), role_properties_copy);
    }

    result
}

#[cfg(test)]
mod tests {
    macro_rules! collection {
        // map-like
        ($($k:expr => $v:expr),* $(,)?) => {
            std::iter::Iterator::collect(std::array::IntoIter::new([$(($k, $v),)*]))
        };
        // set-like
        ($($v:expr),* $(,)?) => {
            std::iter::Iterator::collect(std::array::IntoIter::new([$($v,)*]))
        };
    }

    use super::*;
    use crate::role_utils::{Role, RoleGroup};
    use rstest::*;
    use std::collections::HashMap;

    const ROLE_GROUP: &str = "role_group";

    const ROLE_CONFIG: &str = "role_config";
    const ROLE_ENV: &str = "role_env";
    const ROLE_CLI: &str = "role_cli";

    const GROUP_CONFIG: &str = "group_config";
    const GROUP_ENV: &str = "group_env";
    const GROUP_CLI: &str = "group_cli";

    const ROLE_CONF_OVERRIDE: &str = "role_conf_override";
    const ROLE_ENV_OVERRIDE: &str = "role_env_override";
    const ROLE_CLI_OVERRIDE: &str = "role_cli_override";

    const GROUP_CONF_OVERRIDE: &str = "group_conf_override";
    const GROUP_ENV_OVERRIDE: &str = "group_env_override";
    const GROUP_CLI_OVERRIDE: &str = "group_cli_override";

    #[derive(Clone, Debug, PartialEq)]
    struct TestConfig {
        pub conf: Option<String>,
        pub env: Option<String>,
        pub cli: Option<String>,
    }

    impl Configuration for TestConfig {
        type Configurable = String;

        fn compute_env(
            &self,
            _resource: &Self::Configurable,
            _role_name: &str,
        ) -> Result<HashMap<String, String>, ConfigError> {
            let mut result = HashMap::new();
            if let Some(env) = &self.env {
                result.insert("env".to_string(), env.to_string());
            }
            Ok(result)
        }

        fn compute_cli(
            &self,
            _resource: &Self::Configurable,
            _role_name: &str,
        ) -> Result<HashMap<String, String>, ConfigError> {
            let mut result = HashMap::new();
            if let Some(cli) = &self.cli {
                result.insert("cli".to_string(), cli.to_string());
            }
            Ok(result)
        }

        fn compute_properties(
            &self,
            _resource: &Self::Configurable,
            _role_name: &str,
            _file: &str,
        ) -> Result<HashMap<String, String>, ConfigError> {
            let mut result = HashMap::new();
            if let Some(conf) = &self.conf {
                result.insert("conf".to_string(), conf.to_string());
            }
            Ok(result)
        }

        fn config_information() -> HashMap<String, (PropertyNameKind, String)> {
            todo!()
        }
    }

    fn build_test_config(conf: &str, env: &str, cli: &str) -> Option<TestConfig> {
        Some(TestConfig {
            conf: Some(conf.to_string()),
            env: Some(env.to_string()),
            cli: Some(cli.to_string()),
        })
    }

    fn build_common_config(
        test_config: Option<TestConfig>,
        config_overrides: Option<HashMap<String, HashMap<String, String>>>,
        env_overrides: Option<HashMap<String, String>>,
        cli_overrides: Option<HashMap<String, Option<String>>>,
    ) -> Option<CommonConfiguration<TestConfig>> {
        Some(CommonConfiguration {
            config: test_config,
            config_overrides,
            env_overrides,
            cli_overrides,
        })
    }

    fn build_config_override(
        file_name: &str,
        property: &str,
    ) -> Option<HashMap<String, HashMap<String, String>>> {
        Some(
            collection!( file_name.to_string() => collection!( property.to_string() => property.to_string())),
        )
    }

    fn build_env_override(property: &str) -> Option<HashMap<String, String>> {
        Some(collection!( property.to_string() => property.to_string()))
    }

    fn build_cli_override(property: &str) -> Option<HashMap<String, Option<String>>> {
        Some(collection!( property.to_string() => Some(property.to_string())))
    }

    fn build_role_and_group(
        role_config: bool,
        group_config: bool,
        role_overrides: bool,
        group_overrides: bool,
    ) -> Role<TestConfig> {
        let role_group = ROLE_GROUP.to_string();
        let file_name = "foo.conf";

        match (role_config, group_config, role_overrides, group_overrides) {
            (true, true, true, true) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI),
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)),
                        selector: None,
                }},
            },
            (true, true, true, false) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI), None, None, None),
                    selector: None,
                }},
            },
            (true, true, false, true) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    None,
                    None,
                    None,
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI),
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)),
                        selector: None,
                }},
            },
            (true, true, false, false) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    None,
                    None,
                    None,
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI),
                        None,
                        None,
                        None),
                        selector: None,
                }},
            },
            (true, false, true, true) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        None,
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)),
                        selector: None,
                }},
            },
            (true, false, true, false) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: None,
                    selector: None,
                }},
            },
            (true, false, false, true) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    None,
                    None,
                    None,
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        None,
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)
                    ),
                    selector: None,
                }},
            },
            (true, false, false, false) => Role {
                config: build_common_config(
                    build_test_config(ROLE_CONFIG, ROLE_ENV, ROLE_CLI),
                    None,
                    None,
                    None,
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: None,
                    selector: None,
                }},
            },
            (false, true, true, true) => Role {
                config: build_common_config(
                    None,
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI),
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)),
                        selector: None,
                }},
            },
            (false, true, true, false) => Role {
                config: build_common_config(
                    None,
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI),
                        None,
                        None,
                        None),
                        selector: None,
                }},
            },
            (false, true, false, true) => Role {
                config: None,
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI),
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)),
                        selector: None,
                }},
            },
            (false, true, false, false) => Role {
                config: None,
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        build_test_config(GROUP_CONFIG, GROUP_ENV, GROUP_CLI),
                        None,
                        None,
                        None),
                        selector: None,
                }},
            },
            (false, false, true, true) => Role {
                config: build_common_config(
                    None,
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        None,
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)),
                        selector: None,
                }},
            },
            (false, false, true, false) => Role {
                config: build_common_config(
                    None,
                    build_config_override(file_name, ROLE_CONF_OVERRIDE),
                    build_env_override(ROLE_ENV_OVERRIDE),
                    build_cli_override(ROLE_CLI_OVERRIDE),
                ),
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: None,
                    selector: None,
                }},
            },
            (false, false, false, true) => Role {
                config: None,
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: build_common_config(
                        None,
                        build_config_override(file_name, GROUP_CONF_OVERRIDE),
                        build_env_override(GROUP_ENV_OVERRIDE),
                        build_cli_override(GROUP_CLI_OVERRIDE)),
                        selector: None,
                }},
            },
            (false, false, false, false) => Role {
                config: None,
                role_groups: collection! {role_group => RoleGroup {
                    instances: 1,
                    config: None,
                    selector: None,
                }},
            },
        }
    }

    #[test]
    fn test_transform_all_roles_to_config() {}
}
