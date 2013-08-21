Intro:
The OpenTPM driver creates a device file that can be used to read and write
command blobs directly to the TPM. In Linux a TPM-enabled system can access the /dev/tpm0
device file and control the TPM device via open/read/write commands. This Windows driver
attempts to match that by providing the \\Device\\OPENTPM and \\DosDevices\\OPENTPM
interface to the TPM. 

Usage:
Once the driver is installed, applications should be able to read and write raw TPM command
blobs to \\DosDevices\\OPENTPM using standard winapi calls like CreateFile/ReadFile/WriteFile. 

Install:
open up an elevated cmd.exe
cd into the directory containing install_opentpm.bat
run install_opentpm.bat

Contact:
Corey Kallenberg (ckallenberg@mitre.org)

License:
Copyright 2013 The MITRE Corporation. All Rights Reserved.

GPL v2:
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

MITRE Approved for Public Release; Distribution Unlimited
Case # 13-1595
