# Copyright 2022 alainQtec
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Self-Elevating To prevent UnauthorisedAccess Exceptions, we make sure the commands run as admin:
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $Process = [System.Diagnostics.ProcessStartInfo]::new("PowerShell")
    if ($null -ne $args) {
        $Process.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath' `"$args`";`""
    } else {
        $Process.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    }
    $Process.Verb = "runas";
    [System.Diagnostics.Process]::Start($Process);
    exit
}
Install-Module -Name SecretManagement.Hashicorp.Vault.KV -RequiredVersion 1.1.0