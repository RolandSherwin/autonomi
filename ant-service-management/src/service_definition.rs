// Copyright (C) 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};
use service_manager::{
    ServiceLabel, ServiceManagerKind, WinSwServiceManager, systemd_global_dir_path,
    systemd_user_dir_path,
};
use std::path::{Path, PathBuf};

pub struct ServiceDefinitionReader {
    kind: ServiceManagerKind,
}

impl ServiceDefinitionReader {
    pub fn native() -> Result<Self> {
        let kind = ServiceManagerKind::native().map_err(|err| Error::ServiceManagementFailed {
            reason: format!("Failed to determine native service manager: {err}"),
        })?;
        Ok(Self { kind })
    }

    pub fn has_metrics_port_flag(&self, service_name: &str, user_mode: bool) -> Result<bool> {
        let label: ServiceLabel = service_name.parse().map_err(|err| {
            Error::ServiceLabelParsingFailed {
                reason: format!(
                    "Failed to parse service name '{service_name}' as a service label: {err}"
                ),
            }
        })?;

        match self.kind {
            ServiceManagerKind::Launchd => {
                let dir_path = if user_mode {
                    launchd_user_dir_path()?
                } else {
                    PathBuf::from("/Library/LaunchDaemons")
                };
                let path = dir_path.join(format!("{}.plist", label.to_qualified_name()));
                service_definition_file_has_metrics_port(&path, service_name)
            }
            ServiceManagerKind::Systemd => {
                let dir_path = if user_mode {
                    systemd_user_dir_path().map_err(|err| Error::FileOperationFailed {
                        reason: format!(
                            "Unable to locate config directory for systemd user services: {err}"
                        ),
                    })?
                } else {
                    systemd_global_dir_path()
                };
                let path = dir_path.join(format!("{}.service", label.to_script_name()));
                service_definition_file_has_metrics_port(&path, service_name)
            }
            ServiceManagerKind::OpenRc => {
                let path = PathBuf::from("/etc/init.d").join(label.to_script_name());
                service_definition_file_has_metrics_port(&path, service_name)
            }
            ServiceManagerKind::Rcd => {
                let path = PathBuf::from("/usr/local/etc/rc.d").join(label.to_script_name());
                service_definition_file_has_metrics_port(&path, service_name)
            }
            ServiceManagerKind::WinSw => {
                let qualified_name = label.to_qualified_name();
                let base_dir = WinSwServiceManager::default().config.service_definition_dir_path;
                let path = base_dir
                    .join(&qualified_name)
                    .join(format!("{qualified_name}.xml"));
                service_definition_file_has_metrics_port(&path, service_name)
            }
            ServiceManagerKind::Sc => service_definition_sc_has_metrics_port(&label),
        }
    }
}

fn launchd_user_dir_path() -> Result<PathBuf> {
    let home_dir = dirs_next::home_dir().ok_or_else(|| Error::FileOperationFailed {
        reason: "Unable to locate home directory for launchd user services".to_string(),
    })?;
    Ok(home_dir.join("Library").join("LaunchAgents"))
}

fn service_definition_file_has_metrics_port(path: &Path, service_name: &str) -> Result<bool> {
    if !path.exists() {
        warn!(
            "Service definition file {path:?} for {service_name} was not found; treating as missing metrics port"
        );
        return Ok(false);
    }

    let contents = std::fs::read(path).map_err(|err| Error::FileOperationFailed {
        reason: format!("Failed to read service definition file {path:?}: {err}"),
    })?;
    Ok(String::from_utf8_lossy(&contents).contains("--metrics-server-port"))
}

fn service_definition_sc_has_metrics_port(label: &ServiceLabel) -> Result<bool> {
    let service_name = label.to_qualified_name();
    #[cfg(windows)]
    {
        use std::process::Command;

        let output = Command::new("sc")
            .arg("qc")
            .arg(&service_name)
            .output()
            .map_err(|err| Error::ExecutionFailed {
                reason: format!("Failed to execute sc qc for {service_name}: {err:?}"),
            })?;

        if !output.status.success() {
            return Err(Error::ServiceManagementFailed {
                reason: format!(
                    "Failed to query service {service_name} with sc.exe: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        return Ok(stdout.contains("--metrics-server-port"));
    }
    #[cfg(not(windows))]
    {
        warn!(
            "Service manager kind sc is not supported on this platform; assuming missing metrics port for {service_name}"
        );
        Ok(false)
    }
}
