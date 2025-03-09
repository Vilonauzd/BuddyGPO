# BuddyGPO_EntraIntune

## Overview
  ____ ____   ___  ____            _     _       
 / ___|  _ \ / _ \| __ ) _   _  __| | __| |_   _ 
| |  _| |_) | | | |  _ \| | | |/ _` |/ _` | | | |
| |_| |  __/| |_| | |_) | |_| | (_| | (_| | |_| |
 \____|_|    \___/|____/ \__,_|\__,_|\__,_|\__, |
                                           |___/ 
**BuddyGPO_EntraIntune** is a PowerShell script designed to automate the creation and configuration of Group Policy Objects (GPOs) for Azure Hybrid Join, MDM Auto Enrollment, WinRM, and WinRM Windows Firewall settings in an Active Directory environment. This tool simplifies the process of setting up necessary policies for integrating devices with Microsoft Entra ID (formerly Azure AD) and Intune.

## Features

- **Azure Hybrid Join Policy**: Creates a GPO to enable automatic Azure Hybrid Join.
- **MDM Auto Enrollment Policy**: Configures a GPO for automatic MDM enrollment using Azure AD credentials.
- **Enable WinRM Policy**: Sets up a GPO to enable Windows Remote Management (WinRM) on devices.
- **Allow WinRM Windows Firewall Policy**: Creates a GPO to allow WinRM traffic through the Windows Firewall.

## Prerequisites

1. **PowerShell 5.0 or later** - Ensure PowerShell is installed and updated.
2. **Active Directory Module for PowerShell** - Required for AD-related operations.
3. **Group Policy Management Console (GPMC) Module** - Needed to manage GPOs.
4. **Administrative Privileges** - The script requires administrative privileges to create and modify GPOs.

## Installation

1. Clone the repository or download the script file:
   ```bash
   git clone https://github.com/your-username/BuddyGPO_EntraIntune.git
   ```

2. Navigate to the directory containing the script:
   ```bash
   cd BuddyGPO_EntraIntune
   ```

## Usage

1. **Set Execution Policy** (if necessary):
   - The script includes an option to set the execution policy to `Unrestricted` for the current user, which can be done from within the main menu.

2. **Run the Script**:
   ```bash
   .\BuddyGPO_EntraIntune.ps1
   ```

3. **Main Menu Options**:
   - **Create GPOs**: Navigate to this option to create and configure specific GPOs.
     - **Azure Hybrid Join Policy**
     - **MDM Auto Enrollment Policy**
     - **Enable WinRM Policy**
     - **Allow WinRM Windows Firewall Policy**
   - **Set Domain/OU Path**: Enter your domain name (e.g., `DC=DOMAIN,DC=COM`) and the OU path or domain root for GPO linking.
   - **Set Execution Policy to Unrestricted for Current User**: This option sets the execution policy to allow script execution.

4. **Configuration**:
   - The script will prompt you to enter your domain name and OU path before creating any GPOs.
   - After setting these parameters, you can proceed to create the desired GPOs from the sub-menu.

## Example Workflow

1. Open PowerShell with administrative privileges.
2. Navigate to the directory containing `BuddyGPO_EntraIntune.ps1`.
3. Run the script:
   ```bash
   .\BuddyGPO_EntraIntune.ps1
   ```
4. Follow the on-screen prompts to set your domain and OU path.
5. Select the GPOs you wish to create from the sub-menu.

## Contributing

Contributions are welcome! If you have any improvements, bug fixes, or additional features, feel free to open a pull request. Please ensure your code adheres to the project's coding standards and includes appropriate documentation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: jm@cloudware.host
- **GitHub**: [your-github-profile](https://github.com/vilonauzd)
