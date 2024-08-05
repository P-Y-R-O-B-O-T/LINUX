> [!TIP]
> ### READ SYSTEM DOCS
> * Many tools and file have docs at  `/usr/share/doc`
> * `appropos ROUGH_COMMAND`, to search for a command, but before running this initialize a database using `sudo mandb`
>
> | HELP COMMANDS |
> | ------------- |
> | `COMMAND --help` |
> | `man COMMAND` |
> | `man man` |

## LOG INTO LOCAL and REMOTE CONSOLES
* **Vertual Terminal:** A built-in feature of the Linux operating system that allows users to access multiple windows terminal sessions from a single physical console, press `ctrl+alt+F2`
* **Console:** A system console is the device which receives all kernel messages and warnings and which allows logins in single user mode
* **Terminal Emulator:** A computer program that emulates a video terminal within some other display architecture
* To get all ip addresses associated with your system, run `ip a`
* To ssh into a system, run `ssh USER@IP_HOST_NAME -p PORT`

## HARD LINKS
* All data in linux systems is stored using `Inodes` (these are pointers to data)
* Suppose one user have some data and wants to share it with another one, what to do ? Copy ? Nah !
* We create hard links to it, here in case of hard links, the data do not get duplicated but the same `Inode` gets pointed by multiple files, which saves space on disk `ln /home/USER1/FILE /home/USER2/FILE`
* What if any one user deletes the file ? The file does not get removed because other hard link exist and a file is deleted only if all hardlinks are removed

> [!TIP]
> While creating hard links between users we first add those users to same user group and then give that group write permissions and we need to change permission of one hard link to read and write
> * `useradd -a -G GROUP_NAME USER1 && useradd -a -G GROUP_NAME USER2`
> * `chmod 660 FILE_PATH`
> * `ln /home/USER1/FILE /home/USER2/FILE`

> [!NOTE]
> We can only hard link files, not directories
> We can hard link files only on the same filesystem, we can't hardlink on different filesystems

| COMMAND | EFFECT |
| ------- | ------ |
| `stat FILE` | Get inode data, hardlink data and many more |
| `ln PATH_TO_TARGET_FILE PATH_TO_LINK_FILE` | Create a hard link |

## SOFT LINKS
| COMMAND | EFFECT |
| ------- | ------ |
| `ln -s PATH_TO_TARGET_FILE PATH_TO_LINK_FILE` | Create soft link or symbolic links |
| `ln -l` | Long listing format, see l at starting of properties, that means soft links |
| `readlink` | See target path of a soft link |

## FILE PERMISSIONS
* We can change file group permission only for the groups the user is in, but this behaviour can be changed using `sudo` to set file ownership to any group, even if the user is not part of that group

| COMMAND | EFFECT |
| ------- | ------ |
| `chgrp GROUP_NAME FILE_DIRECTORY_PATH` | Change group of file or directory |
| `chown USER FILE_DIRECTORY_PATH` | Change owner of file or directory |
| `chown USER:GROUP_NAME FILE_DIRECTORY_PATH` | Change user owner and group owner |
| `chmod ACCESS+PERMISSIONS FILE_DIRECTORY_PATH` | Add permissions, `ACCESS` can be `u`, `g`, `o` and PERMISSIONS can be `r`, `w`, `x`, `rx`, `rw`, `rwx` |
| `chmod ACCESS-PERMISSIONS FILE_DIRECTORY_PATH` | Remove permissions, `ACCESS` can be `u`, `g`, `o` and PERMISSIONS can be `r`, `w`, `x`, `rx`, `rw`, `rwx` |
| `chmod ACCESS=PERMISSIONS FILE_DIRECTORY_PATH` | Set exact permissions, `ACCESS` can be `u`, `g`, `o` and PERMISSIONS can be `r`, `w`, `x`, `rx`, `rw`, `rwx` and ` ` for no permissions |
| `chmod NNN FILE_DIRECTORY_PATH` | Set permissions in octal format, there are 3 digits, for user, group and others |

> [!TIP]
> ### COMBINED COMMANDS EXAMPLE
> `chmod u+rw,g=r,o=x FILE_DIRECTORY_PATH`
> `chmod 767 FILE_DIRECTORY_PATH`

> [!NOTE]
> * If a file have the permission `----rwxrwx` and the owner tries to read the file, would not be able to read it but any other user belonging to owner's group will be able to read it as the permissions are read and evaluated from left to right
> * First it check the user, if it is owner then dont allow access then see group if user is in valid group, allow the file access

> [!TIP]
> ### PERMISSIONS and FILE IDENTIFYER
> * We can see it in long listing format
> ```
> IDENTIFIER OWNER_PERM GROUP_PERM OTHERS_PERM
> ```
> * All of these can hve value of 
>
> | VALUE | OCTAL VALUE | PERMISSION |
> | ----- | ----------- | ---------- |
> | `---` | 0 | No permission |
> | `r--` | 4 | Read |
> | `-w-` | 2 | Write |
> | `--x` | 1 | Execute |
> | `rw-` | 6 | Read write |
> | `r-x` | 5 | Read execute |
> | `-wx` | 3 | Write execute |
> | `rwx` | 7 | Read write execute |
>
> | FILE TYPE | IDENTIFIER |
> | --------- | ---------- |
> | Directory | `d` |
> | Regular File | `-` |
> | Character Device | `c` |
> | Link | `l` |
> | Socket File | `s` |
> | Pipe | `p` |
> | Block Device | `b` |

## SUID and GUID
* We want to give permission to other user but not full control over files like to delete or modify or access as root without permission
* If a file sticky bit has given permission with execurion as sticky bit, if other user executes it, it runs with owner's permission, it will run as owner's user, not that user's permission, not as that user
* If we see a `S` on running `ls -l`, stick bit set but no execute permission
* If we see a `s` on running `ls -l`, sticky bit set and execute permission given
* If we see a `T` on running `ls -l` in other permissions section, sticky bit set and no execute permission
* If we see a `t` on running `ls -l` in other permissions section, sticky bit set and execute permission given

| COMMAND | EFFECT |
| ------- | ------ |
| `chmod SUGO FILE_DIRECTORY_PATH` | Define sticky bit for `SUID` and `GUID` and all of other user only to read it but can't delete, `S` can have the octal values `4` for user, `2` for group and `6` if sticky bit needs to be applied to both the group and user and `1` for others |
| `find . -perm /N000` | Fing files with sticky bit, n can be `2`, `4`, `6` |

## FIND FILES
| COMMAND | EFFECT |
| ------- | ------ |
| `find SEARCH_PATH -name FILE_DIRECTORY_PATH_TO_BE_SEARCHED` | Find files and directories |
| `find -iname FILE_DIRECTORY_PATH_TO_BE_SEARCHED` | Find file and directories in case insensitive manner |
| `find -name "REGEX"` | Find using regex |
| `find -mmin -N` | Find files that were modified in last `N` minutes |
| `find -mmin +N` | Find files modified atleast `N` minutes ago |
| `find -mtime N` | Find files that were modified between last `N*24` and `(N-1)*24` hours ago |
| `find -cmin -N` | See files whose permissions changed in last `N` minutes |
| `find -size FILE_SIZE` | `FILE_SIZE` can be `Nk`, `nG`, `nc`, `nM` |
| `find -size -FILE_SIZE` | `FILE_SIZE` can be `Nk`, `nG`, `nc`, `nM`, files less than the size |
| `find -size +FILE_SIZE` | `FILE_SIZE` can be `Nk`, `nG`, `nc`, `nM`, files greater than the size |
| `find -perm UGO` | Find files with exact permissions |
| `find -perm -UGO` | Find files with at least these permissions |
| `find -perm /UGO` | Find files with any of these permissions for respective user, group and others |

> [!TIP]
> OR condition in search expression `find SEARCH_PATH -size -FILE_SIZE -o -cmin -N`
> The `-o`
> NOT condition in search expression `find SEARCH_PATH --not -size -FILE_SIZE -o -cmin -N`, here NOT applies to only file size

> [!TIP]
> `Change time != Modification time`
> Change time = time at which metadata was changed
> Modification time = time at which file was modified

## FILE EDITING AND ACCESSING

| COMMAND | EFFECT |
| ------- | ------ |
| `tail -n N FILE` `head -n N FILE` | See files in buffers with `N` lines |
| `sed 's/WORD_TO_BE_REPLACED/WORD_THAT_TAKES_PLACE/g' FILE_PATH` | Replace all occurences of a sequence in a file |
| `sed -i 's/WORD_TO_BE_REPLACED/WORD_THAT_TAKES_PLACE/g' FILE_PATH --in-place` | Replace inplace without printing in the terminal |
| `sed 's/WORD_TO_BE_REPLACED/WORD_THAT_TAKES_PLACE' FILE_PATH` | Do not change the file but see the changes in terminal |
| `cut -d 'DELIMITER' -f N FILE_PATH` | Get `N`th column from file where all columns are seperated by delimiter |
| `uniq FILE_PATH` | Get unique entries from a file, NOTE: only consecutive repeating entries get removed |
| `sort FILE_PATH` | Sort a file |
| `sort FILE_PATH \| uniq` | Remove all repeating entries |

> [!TIP]
> `colordiff`
> Pagers `less` `more`

## SEARCH USING FILE

| COMMAND | EFFECT |
| ------- | ------ |
| `grep -i 'SEARCH_PATTERN' FILE_PATH` | Search for pattern in file without case sensitivity |
| `grep -r 'SEARCH_PATTERN' DIRECTORY` | Search in all files in a directory |
| `sudo grep -ri --color 'SEARCH_PATTERN' DIRECTORY` | Force color and avoid permission denied |
| `grep -w 'SEARCH_PATTERN' FILE_PATH` | Search for exact word with non alphanumeric characters on both end |
| `grep -o 'SEARCH_PATTERN' FILE_PATH` | Search for only matching pattern, do not print complete line, print only the matched pattern |

## BACKUP and ARCHIVE

> [!NOTE]
> While extracting tarball, all files retain metadata like user access and many more things, so if `user1` created a file with `x` permission and `user2` copying it, it can give error while creation of that file because it is not owned by `user2`, in that case use `sudo`

| COMMAND | EFFECT |
| ------- | ------ |
| `tar --list --file TARBALL_FILE` | List content of tarball |
| `tar --create --file TARBALL_FILE_PATH FILE_DIRECTORY_PATH` | Create a tarball |
| `tar --append --file TARBALL_FILE_PATH FILE_DIRECTORY_PATH` | Add items to a existing tarball |
| `tar --extract --file TARBALL_FILE_PATH` | Extract a tarball in current directory |
| `tar --extract --file TARBALL_FILE_PATH --directory DIRECTORY_PATH` | Extract a tarball in specifie directory |

## COMPRESSION
* Mainly 3 utilities are there `gzip`, `bzip`, `xz`

| COMMAND | EFFECT |
| ------- | ------ |
| `gzip --keep TARBALL_FILE` | Compress |
| `bzip2 --keep TARBALL_FILE` | Compress |
| `xz --keep TARBALL_FILE` | Compress |
| `gunzip --keep GZIP_FILE` or `gzip --keep --decompress GZIP_FILE` | Decompress |
| `bunzip --keep BUNZIP_FILE` or `bzip2 --keep --decompress BUNZIP_FILE` | Decompress |
| `unxz --keep XZ_FILE` or `xz --keep --decompress XZ_FILE` | Decompress |

## SAFELY BOOT REBOOT

| COMMAND | EFFECT |
| ------- | ------ |
| `sudo systemctl reboot` | Safe reboot |
| `sudo systemctl poweroff` | Safe poweroff |
| `sudo systemctl reboot --force` | Forcefully reboot |
| `sudo systemctl poweroff --force` | Forcefully poweroff |
| `sudo systemctl reboot --force --force` | Very insecure, its like pulling power cable from computer
| `sudo systemctl poweroff --force --force` | Very insecure, its like pulling power cable from computer
| `sudo shutdown 18:15` | Power off at 18:15 |
| `sudo shutdown +15` | Power off in 15 mins |
| `sudo shutdown -r +15` | Reboot after 15 mins |
| `sudo shutdown -r +10 'Rebooting system wall message'` | Reboot and notify logged in users what is about to happen |

> [!TIP]
> ### BOOT SYSTEM IN DIFFERENT MODES
> * When we boot into the system, we boot into the `default.target`
> * We can see the default target using `systemctl get-default`
> * `graphical.target` is for booting into GUI mode, `multi-user.target` is for booting into the linux shell target (the black box screen)
> * We can change the default target using `systemctl set-default multi-user.target`
> * Switch back to graphical target from the `multi-user.target` `systemctl isolate graphical.target`, this is not permanant, it is only for the current session
> * `emargency.target` is for debugging the boot process and other problems that are caused by different systems, this also marks the root fs as read-only
> * `rescue.target` only essential services are loaded and we are logged into root shell

## SHELL AUTOMATION
| COMMAND | EFFECT |
| ------- | ------ |
| `chmod +x FILE` | Make executable for everyone |
| `chmod u+x FILE` | Mmake executable for current user |

## MANAGE STARTUP PROCESSES
* Processe are started by a init system
* Systemd is a collection of tools that helps start, operate and manage services and processes, it is also a init system

| COMMAND | EFFECT |
| ------- | ------ |
| `systemctl cat SYSTEMD_FILE` | See the systemd file content |
| `systemctl edit --full SYSTEMD_FILE` | Edit the systemd file |
| `systemctl revert SYSTEMD_FILE` | Revert the changes to the file to factory settings |
| `systemctl status SERVICE_NAME` | See status of service |
| `systemctl stop SERVICE_NAME` | Stop a service |
| `systemctl start SERVICE_NAME` | Start a service |
| `systemctl restart SERVICE_NAME` | Restart a service but this can abrupt the current process that may be associated with other processes and users |
| `systemctl reload SERVICE_NAME` | Reload service without interrupting the processes and in-memory data
| `systemctl disable SERVICE_NAME` | Disable the service
| `systemctl enable SERVICE_NAME` | Enable the service
| `systemctl enable --now SERVICE_NAME` | Enable and start the service
| `systemctl disbale --now SERVICE_NAME` | Disable and stop the service
| `systemctl mask SERVICE_NAME` | Sometimes a service starts automatically and starts other serivices too, to stop this thing we need to mask the service
| `systemctl unmask SERVICE_NAME` | Unmask the masked service
| `systemctl list-units --type UNIT_TYPE --all` | List all serices of a type, there are many types of services: `service`, `socket` etc

## SYSTEMD SERVICES

| COMMAND | EFFECT |
| ------- | ------ |
| `man systemd.<TAB><TAB>` | Get to know about service units |
| `journalctl -f` | See live logs generated by systemd services |

* See existing systemd files at `/lib/systemd/system`

## DIAGNOSE and MANAGE PROCESSES

| COMMAND | EFFECT |
| ------- | ------ |
| `man ps /EXAMPLES` | See most used `ps` examples |
| `ps` | List processes running in current terminal session |
| `ps -aux` | List all processes, processes shown in bracket area are privilaged processes running in kernel mode |
| `ps u PID` | See process data in user oriented format (see process cpu and mem utilisation) |
| `ps u -U USER_NAME` | See processes launched by current user in user oriented format |
| `pgrep -a MATCH_STRING` | Search process by name or match_string |
| `nice -n NICE_VALUE COMMAND` | Run a process with a nice value, there are enice values thich can define process priority [-20, 19], more the value, less the cpu it consumes |
| `ps l` | See processes with nice values |
| `ps fax` | See all processes with child parent relationship |
| `renice NEW_NICE_VALUE PID` | Change nice value |
| `kill -L` | Get list of signals for processes |
| `kill -SIGNAL PID` | Send a signal to the process |
| `pkill -SIGNAL PROCESS_NAME` | Send signal to all processes matching the name |
| `COMMAND &` | Run process in background |
| `fg PROCESS_HINT` | Bring back the process in foreground |
| `lsof -p PID` | See all files and directories being used by a process |
| `lsof FILE_DIRECTORY_PATH` | See if any process is using the file or directory |

> [!IMPORTANT]
> * While using kill command be sure of these basic signals
>
> | SIGNAL | EFFECT |
> | ------ | ------ |
> | `SIGSTOP` | Stop the process in the same atate and keem in memory |
> | `SIGCONT` | Resume a stopped process |
> | `SIGTERM` | Terminate a process and give it time to do the necessary time to cleanup and persist data |
> | `SIGKILL` | Forcefully kill the process |


> [!TIP]
> ### SCHEDULING TASKS
> * We can schedule tasks using cron, anacron and at
> * Anacron runs the task even if the computer was off at the time of execution but cron won't
> * `cat /etc/crontab` to see the cronjob format
> * For each star if we want to run in ranges or multiple values of theat field, we can use:
>     - `,` to match multiple values without having space inbetween the value and comma (like 2,5)
>     - `-` for specifying the ranges (like 2-4)
>     - `/` can be used to specify the step values (skip values) (like /4)
> * Always use full command path
> * Cronjobs are user specific
> * `sudo cronjob -e -u USERNAME` edit other user's cronjobs
> * `at` command is used to run a task once


## LOG FILES
* `rsyslog` service saves all the logs in `/var/log/`
* Main files that are frequently used are `/var/log/syslog` and `/var/log/auth.log`

| COMMAND | EFFECT |
| ------- | ------ |
| `grep -r ssh /var/log/` | Get file that strores ssh logs |
| `tail -F LOGFILE` | See live logs |
| `journalctl COMMAND_SYSTEMD_UNIT` | See logs generated by the command or systemd unit |
| `journalctl -f` | See live logs |
| `journalctl -p PRIORITY` | See logs filtered by priority, priorities are: `info`, `warning`, `err` and `crit` |
| `journalctl -p PRIORITY -g 'REGEX'` | See regex matching logs with selected priority |
| `journalctl -S START_TIME -U END_TIME` | See logs in between time period, time format is `HH:MM` |
| `journalctl -b 0` | Get loge for current boot |
| `journalctl -b -N` | See logs for previous boots |
| `last` | See login activity |
| `lastlog` | See who logged last |

## PACKAGE MANAGEMENT
* Specifically for apt package manger

| COMMAND | EFFECT |
| ------- | ------ |
| `apt search --name PACKKAGE_NAME` | Search package in module names and their descriptions |
| `apt search --names-only PACKKAGE_NAME` | Search only in module names |
| `apt install PACKKAGE_NAME` | Install a package |
| `apt remove PACKKAGE_NAME` | Remove package, but do not remove dependencies |
| `apt autoremove PACKKAGE_NAME` | Remove the dependencies along with the main package |

* The file `/etc/apt/sources.list.d/ubuntu.sources` stores all the repositories that apt is supposed to search and use

## VERIFY AVAILABILITY OF RESOURCES

| COMMAND | EFFECT |
| ------- | ------ |
| `df` | See the disk free space |
| `df -h` | See the disk space in human readable format |
| `du -sh PATH` | See the space being used by a directory |
| `free -h` | See available ram and swap |
| `uptime` | See system isge throughout the boot time |
| `fsck.ext4 -v -f -p PATH_TO_DISK_DEVICE` | Repair disk with verbose, force and pre options |

## CHANGE KERNEL RUNTIME PARAMETERS (PERSISTENT and NON PERSISTENT)

| COMMAND | EFFECT |
| ------- | ------ |
| `sysctl -a` | Read some parameter values |
| `sysctl -w PARAMETER=VALUE` | Write values to a parameter, non presistent change |
| `man sysctl.d` | Get help on system parameter configuration files |

* We can also edit the existing file `/etc/sysctl.conf`

> [!TIP]
> ### MAKE PERSISTENT CHANGE
> * Make a file `touch /etc/sysctl.d/FILE_NAME.conf`, we can give any name
> * Add the line `vm.swappiness=20` and then save, this makes the vm less swappy
> * This will persist even after reboot
> * These changes normally apply after reboot, to get into action quickly run `sysctl -p /etc/sysctl.d/FILE_NAME.conf`

## CREATE DELETE MODIFY USER and GROUPS

| COMMAND | EFFECT |
| ------- | ------ |
| `adduser USER_NAME` | Creates a user, also creates a new group called USER_NAME |
| `passwd USER_NAME` | Change or enter a new password |
| `deluser USER_NAME` | Delete a user, but if someone else is in its group, group stays and /home/USER_NAME is not removed |
| `adduser --shell /bin/OTHER_SHELL --home /home/OTHER_DIRECTORY USER_NAME` | Specify alternative shall and home directory |
| `cat /etc/passwd` | See account details |
| `adduser --uid UID USER_NAME` | Specify UID |
| `ls -la` | Get user and owner permissions |
| `ls -lna` | Get user and owner premissions in UID |
| `id` | Get current user info |
| `useradd --system --no-create-home USER_NAME` | Create a system account without home directory |
| `usermod --home /home/OTHER_DIRECTORY --move-home USER_NAME` | Change the home directory of a user |
| `usermod --login NEW_USER_NAME OLD_USER_NAME` | Change username |
| `usermod --shell /bin/OTHER_SHELL USER_NAME` | Change default shell |
| `usermod --lock USER_NAME` | Lock/Disable the account without deleting it |
| `usermod --unlock USER_NAME` | Unlock the account |
| `usermod --expiredate YYYY-MM-DD USER_NAME` | Expire the account on date, can be re-enabled |
| `chage --maxdays N USER_NAME` | Force user to change the password every N days |
| `chage --maxdays -1 USER_NAME` | Make user password never expires |
| `chage --lastday 0 USER_NAME` | Expire user password for the user |
| `chage --lastday -1 USER_NAME` | Unexpire the user password |
| `groupadd GROUP_NAME` | Create a group |
| `gpasswd --add USER_NAME GROUP_NAME` | Add user to group |
| `gpasswd --delete USER_NAME GROUP_NAME` | Remove a user from group |
| `groups USER_NAME` | See the groups that the user is part of |
| `usermod -g GROUP_NAME USER_NAME` | Change primary group of user |
| `usermod -G GROUP_NAME USER_NAME` | Change secondary group of user |
| `groupmod --new-name NEW_GROUP_NAME OLD_GROUP_NAME` | Change group name |
| `groupdel GROUP_NAME` | Delete group, but be careful, no user should have this group as primary |

## MANAGE ENVIRONMENT PROFILES
* To save variables in local profile, save them in `/home/usr/.bashrc`
* To save variables in all profiles, save then in `/etc/environment`
* To run a task when a user logs in, create a file `/etc/profile.d/FILE_NAME.sh` and add all the commands that are need to be run

| COMMAND | EFFECT |
| ------- | ------ |
| `printenv` | List environment parameters |
| `echo $ENV_VARIABLE` | Print environment variable value |

> [!TIP]
> ## MANAGE TEMPLATE USER ENVIRONMENT
> * When a user is created, all items from `/etc/skel/` are copied to new user's home directory
> * We put all the files in there and they will be copied

## USER RESOURCE LIMITS
* To do this we can edit `/etc/security/limits.conf`
* Syntax for Each entry is `DOMAIN LIMIT_TYPE RESOURCE_ITEM VALUE`
* `DOMAIN` could be `USER_NAME` or `@GROUP_NAME`, and `*` is for all users not mentioned specifically in the entries of this file
* `LIMIT_TYPE` could be hard, soft or \-
    - `hard` is used for max value that can ever be used
    - `soft` is used for startup resource limits
    - \- is used for both hard and soft limit, it defines both as same value
* `RESOURCE_ITEM` defines type fo resource to limit (like nproc, cpu, fsize)
* To seek for more help `man limits.conf`

## MANAGE USER PRIVILAGES
* Most of the users are in the sudo group and can run all the commands after entering the password, but this is a issue
* To solve this we need to edit the `/etc/sudoers`
* The systax for the sudoers file is `USER IP_HOST_NAME=(RUN_AS_USER:RUN_AS_GROUP) LIST_OF_COMMANDS_THAT_ARE_ALLOWED_TO_BE_EXECUTED`
* All parameters except the `USER` can be entered with comma seperated without space
* Examples
    - `USER1 ALL=(USER2,USER3) /bin/COMMAND1, /bin/COMMAND2`, this allows USER1 to run COMMAND1 and COMMAND2 as sudo as USER2 and USER3
    - `USER_NAME ALL=NOPASSWD:ALL`, this allow running sudo commands wothout password
    - `%GROUP_NAME ALL=(ALL) ALL`

* To run a command as other user `sudo -u USER_NAME COMMAND ARGUMENTS`

## MANAGE ACCESS TO ROOT ACCOUNT
* In some systems, root account is locked for security purposes but this does not mean we can't login with the root

| COMMAND | EFFECT |
| ------- | ------ |
| `sudo --login` | Login into the shell as root user |
| `su -` | Login into the shell as root user, we need to enter the root user password insteat of the current user |
| `sudo passwd --unlock root` | Unlock the root user |
| `sudo passwd root` | Change or create a password for root |
| `passwd --lock root` | Everyone using root is insecure, so we lock the password based logins |


## CONFIGURE IPv4 and IPv6 NETWORKING and HOSTNAME RESOLUTION
* IPv6 and IPv4 both have a CIDR notation
* IPv6 addresses can be written in short by removing leading zeroes (`2001:0db8:0000:0000:0000:ff00:0042:8378` \-> `2001:db8::ff0042:8378`)
* The `ip` command can help us get all important info about our network configuration
* A network interface can have multiple IPs, sometimes they need to be removed or added

> [!TIP]
> ### CHANGE SYSTEMWIDE DNS
> * To apply nameserver setting to all network interfaces, edit `/etc/systemd/resolved.conf` and add the following `DNS=IP_ADDRESSES`, `IP_ADDRESSES` are the IP addresses seperated by spaces and then restart the systemd resolver daemon by running `systemctl restart systemd-resolver.service`

> [!TIP]
> ### REFER INTERNAL HOSTS BY NAME
> * Sometimes we have a internal server for some purposes, we cant remember all the IP addresses, so we add he names of servers in the file `/etc/hosts`
> * We make an entry in the format `IP NAME` 

| COMMAND | EFFECT |
| ------- | ------ |
| `ip link` | Shows all networking interfaces on the device |
| `ip -c address` | Shows ip addresses for all the networking interfaces |
| `ip link set dev INTERFACE_NAME up` | Activate a networking interface connection |
| `ip link set dev INTERFACE_NAME down` | Deactivate a networking interface connection |
| `ip addr add CIDR dev INTERFACE_NAME` | Manually add IPv4 address, specify the address and add an IP, CIDR example is `192.168.1.9/24` |
| `ip addr add IPv6_CIDR INTERFACE_NAME` | Manually add IPv6 address, specify the address and add an IP, CIDR examples is `fe80::5054:ff:fe1f:8050/64` |
| `ip addr delete CIDR dev INTERFACE_NAME` | Remove a IP address from an interface, after this we need to bring back the device down |
| `ip route` | See the routes to different destinations |
| `resolvectl status` | See the nameserver configuration for all the interfaces |
| `systectl restart systemd-resolver.service` | Restart the DNS resolver daemon to apply changes in `/etc/systemd/resolved.conf` |

* All these changes are temporary, to make these changes permanent, we use netplan
* The netplan files is present at `/etc/netplan/`, we can edit those or create our own
* New file's name will be in format `NN-NAME.yaml`, where NN are single digit numbers
* Then see a already existing file and start making changes according to ahat we need
* The DHCP server loop runs on the router
* Netplan files might look like these for wireless interfaces
```
network:
  version: 2
  wifis:
    NM-325453d5-9061-49ab-ae2a-1f8f8f9f01bf:
      renderer: NetworkManager
      match:
        name: "wlp0s20f3"
      dhcp4: true
      dhcp6: true
      access-points:
        "POCO C65":
          auth:
            key-management: "psk"
            password: "avadakadabra"
          networkmanager:
            uuid: "325453d5-9061-49ab-ae2a-1f8f8f9f01bf"
            name: "POCO C65"
            passthrough:
              wifi-security.auth-alg: "open"
              ipv6.addr-gen-mode: "default"
              ipv6.ip6-privacy: "-1"
              proxy._: ""
      networkmanager:
        uuid: "325453d5-9061-49ab-ae2a-1f8f8f9f01bf"
        name: "POCO C65"
```

| COMMAND | EFFECT |
| ------- | ------ |
| `netplan get` | Get all info for all network interfaces |
| `netplan try` | Try the changes defined in the netplan file |
| `netplan apply` | Aply changes made to netplan file |

* Lets configure the file with a ethernet device
```
network:
  ethernets:
    enp0s8:
      dhcp4: false
      dhcp6: false
      addresses:
        - 192.168.1.9/24
        - f380::921b:eff:fe3d:abcd/64
      nameservers:
        addresses:
          - 8.8.4.4
          - 8.8.8.8
      routes:
        - to: 192.168.0.0/24
          via: 10.0.0.100
        - to: default
          via: 10.0.0.1
  version: 2
```
* We can get great netplan examples at `/usr/share/doc/netplan/examples/`
* For more help `man netplan`, `man ip`

## START STOP and MANAGE NETWORK SERVICES

| COMMAND | EFFECT |
| ------- | ------ |
| `ss -ltunp` | Tells which interface and and ports are being used in the system |
| `netatst -ltunp` | same as that command above |

## PORT REDIRECTION and NAT
* Port forwarding allows remote servers and devices on the internet to be able to access devices that are on a private network
* We can enable port forwarding in linux by editing `/etc/sysctl.conf` or `/etc/sysctl.d/99-sysctl.conf`, editing the first one is riskier
* Open the second file and add or uncomment the following lines
```
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
```
* Generally input and output network interfaes and input network interfaces are different but can be same in some cases
* After editing the file reload all sysctl config files by running `sudo sysctl --system`
* For adding fine tuned working rules in nat table we need to do both pre routing and post routing things

| COMMAND | EFFECT |
| ------- | ------ |
| `ip r` | See all the routes |
| `iptables -t nat -A PREROUTING -i INPUT_INTERFACE_NAME -s SOURCE_CIDR -p tcp --dport DESTINATION_PORT -j DNAT --to-destination IP_HOST_NAME:PORT` | Add a rule to NAT table in append manner with prerouting packet modification to jump the packets in DNAT manner |
| `iptables -t nat -A POSTROUTING -s SOURCE_CIDR -o OUTPUT_INTERFACE_NAME -j MASQUERADE` | Add a rule to nat table for masquerading with post routing |
| `iptables --list-rules --table nat` | See all nat rules |
| `iptables --flush --table nat` | Delete all the rules from the nat table |

* All the changes made by these command are temporary and are lost at next boot up, to make these changes permanent install a package `iptables-persistent` from apt and after adding the rule to chain, run `netfilter-persistent save`

* This stuff can be done using ufw too

| COMMAND | EFFECT |
| ------- | ------ |
| `ufw route allow from INPUT_CIDR to TARGET_MACHINE_IP` | Allow port forwarding |

## SYNCHRONIZE SYSTEM TIME
* Our systems can utilize time servers to get exact time from the internet

| COMMAND | EFFECT |
| ------- | ------ |
| `timedatectl list-timezones` | Get all available timezones |
| `timedatectl set-timezone TIMEZONE` | Set system timezone |
| `timedatectl` | Get timezone and system time info and see if any NTP server is active |
| `apt install systemd-timesyncd && timedatectl set-ntp true` | If no active NTP servers found, we turn on synchronization with NTP servers |
| `systemctl status systemd-timesyncd.service` | See if NTP service is actine or not |

## MANAGE PHYSICAL STORAGE PARTITIONS
* Bulk devices are the devices from which we can read and write to some data
    - These devices can be seen to be having names starting from `nvme`, `sda`, `sdb`, `sdc` where `sd` stands for storage device and `a, ,b c` denote the number od disk like `1, 2, 3` and many more
    - Then we have partition reference like `sda1, sda2` which are the physical partions on the disks
    - There is a asying in linux that everything is a file, all these storage device files can be listed in `/dev/` like `/dev/nvme0n1` and many more
    - There are partition tables that knows whare a partition starts and ends, for a decade `Master Boot Record (MBR)` was use but now transitioned to ` Grid Partition Table (GPT)` which supports less corruption of data and provide more versatile partitioning options 

| COMMAND | EFFECT |
| ------- | ------ |
| `lsblk` | List bulk devices |
| `findmnt` | See all mounted devices and see verbose info about them |
| `fdisk --list /dev/DEVICE_NAME` | See partitions in bulk device |
| `cfdisk /dev/DEVICE_NAME` | Disk partitioning utility |
| `swapon --show` | See the swap areas that the system is aware of and using |
| `mkswap --verbose /dev/PARTITION_NAME` | Make the swap area from the swap partion that we create using the cfdisk tool, this change is temporary and does not work after reboot |
| `swapon /dev/PARTITION_NAME` | Tell os to use the partition or file as swap after running `mkswap /dev/PARTITION_NAME` |
| `swapoff /dev/PARTITION_NAME` | Tell os to stop using the partion or file as swap |
| `dd if=/dev/zero of=SWAP_FILE_PATH bs=1M count=128 status=progress && chmod 600 SWAP_FILE_PATH && mkswap SWAP_FILE_PATH && swapon --verbose SWAP_FILE_PATH` | Create a file based swap, file should not to exist before running these commands, as we are creating the file first |
im
> [!IMPORTANT]
> ### CREATING PARTITIONS
> * Launch `cfdisk /dev/DEVICE_NAME`
> * Select GPT
> * Select a Free Space and select `new`
> * Enter size and then Hit `Enter`
> * Similarly again select Free space and then create new partition
> * Select `write` option to write the changes to the device

> [!IMPORTANT]
> ### RESIZE PARTITIONS
> * If we want to resize a partition, goto that partition select `resize` and hit `Enter`
> * Then enter the new size and hit `Enter`
> * Partitions are ordered in order of creation, not based on the physical location
> * To solve the issue, goto the `sort` option an hit `Enter`
> * Select `write` option to write the changes to the device

> [!IMPORTANT]
> ### CREATE SWAP
> * Select the partition and then select `type` option
> * Select `linux swap` and hit `Enter`
> * Select `write` option to write the changes to the device

> [!IMPORTANT]
> ### CREATE BOOT PARTITION
> * Select partition and then select `type` option
> * Select `EFI partition` and then hit `Enter`
> * Select `write` option to write the changes to the device
> * Select `write` option to write the changes to the device

> [!TIP]
> ### CREATE and MANAGE SWAP USING DEVICES
> * Create a swap partition using the `cfdisk` tool on a device 
> * Create a swap using `mkswap --verbose /dev/PARTITION_NAME`

> [!TIP]
> ### CREATE SWAP FROM FILES
> * `dd if=/dev/zero of=/swap bs=1M count=1024 status=progress`
> * `dd` is a command to write things or bombard things
> * `/dev/zero` is a file that can generate infinite number of zeroes when an application reads it
> * `bs` defines the base size of file unit
> * `count` defines how many bs units define the swap file (totalsize=bs*count)
> * `of` is for output file and we are writing to `/swap`, it colud be any other name
> * Memory content will be written by linux to it, so we should restrict access to ensure salefy by `chmod 600 /swap`
> * Then we declare it as swap `mkswap /swap`

## CREATE and CONFIGURE FILE SYSTEM

| COMMAND | EFFECT |
| ------- | ------ |
| `mkfs.ext4 /dev/PARTITION_NAME` | Create a ext4 filesystem in selected partition |
| `mkfs.xfs /dev/PARTITION_NAME` | Create xfs filesystem in selected partition |
| `mkfs.ext4 -L "PARTITION_LABEL" -i size=INODE_SIZE /dev/PARTITION_NAME` | Create a filesystem with a label and inode size in bytes |
| `xfs<TAB>` | Get xsf utility commands |
| `ext4<TAB>` | Get ext4 utility commands |
| `mkfs.ext4 /dev/PARTITION_NAME -f` | Force to reformat the filesystem if it already exists |
| `mkfs.ext4 -i size=INODE_SIZE -N NUMBER_INODES` | Create partition with inodesize and number of inodes |
| `man mkfs.ext4` | get help for creating ext4 partition |
| `fdisk -l` | List all filesystems |
| `xfs_admin -L "PARTITION_LABEL" /dev/PARTITION_NAME` | Change label and other properties of xfs using this command |
| `tune2fs -l /dev/PARTITION_NAME` | See all properties of a partition |
| `tune2fs -L "PARTITION_LABEL" /dev/PARTITION_NAME` | Change the label of ext4 partition |

## MOUNTING FILESYSTEMS
* To make a filesystem accessable, we must mount it
* All the filesystem are mounted inside the directory `/mnt/` but not necessarily, `MOUNT_POINT` can be any existing directory

| COMMAND | EFFECT |
| ------- | ------ |
| `mount /dev/PARTITION_NAME MOUNT_POINT` | Mount a filesystem to the mount point path |
| `umount MOUNT_POINT` | Unmount a filesystem |
| `systemctl daemon-reload` | To reflect all the changes after editing the `/etc/fstab` |
| `man fstab` | See halp for `/etc/fstab` file |
| `blkid /dev/PARTITION_NAME` | Get UUID of partition on he bulk device |

> [!TIP]
> ### AUTOMATICALLY MOUNT FILESYSTEMS
> * `/etc/fstab` is the file where all mounts are defined
> * The format is `/dev/PARTITION_NAME MOUNT_POINT FILESYSTEM MOUNT_OPTIONS DUMP_VALUE CORRUPTION_ERROR_HANDLE`
>     - `FILESYSTEM` can be `ext4`, `xfs` and many more
>     - `MOUNT_POINT` is the absolute path
>     - `MOUNT_OPTIONS` normally we use it with value `defaults`
>     - `DUMP_VALUE` is used for backup of this filesystem : `0` for disable `1` for enable
>     - `CORRUPTION_ERROR_HANDLE` to decide what to do when error is encountered, we generally use the value `2`
>         - `0` means never scan the filesystem for errors
>         - `1` means scan before the oter ones, generally for root filesystem of os
>         - `2` scan the fs when the ones with value `1` are scanned

> [!TIP]
> ### CREATE and MOUNT SWAP PERSISTENTLY
> * Change the `/etc/fstab` and enter the following
> * `/dev/PARTITION_NAME none swap defaults 0 0`, where PARTITION_NAME is the swap partition we created using the `cfdisk` tool
> * Run `swapon --show` to ensure it is being used as swap

> [!IMPORTANT]
> ### ENSURING CORRECT FUNCTIONALITY
> * Sometimes a computer have multiple ssd or hdd slots and changing the disks from one to other slots can lead to bad results, so we use UUID of a bulk device instead of `sdx`, because `sdx` is relative to ports and slots in motherboard and the time sequence of connecting the devices and we can see entrien in `/etc/fstab` whick look like `/dev/disk/by-uuid/75a33bb5-cbb7-4b02-bccf-1fb5cad46ea5 /boot ext4 defaults 0 1` which follows the format `/dev/disk/by-uuid/UUID MOUNT_POINT FILESYSTEM MOUNT_OPTIONS DUMP_VALUE CORRUPTION_ERROR_HANDLE`
> * To get UUID of a bulk device `blkid /dev/PARTITION_NAME` or we can see 

> [!IMPORTANT]
> ### MOUNT OPTIONS 
>
> | COMMAND | EFFECT |
> | ------- | ------ |
> | `mount -o MOUNT_OPTIONS /dev/PARTITION_NAME MOUNT_POINT` | Provide mount options to the mount, `MOUNT_OPTIONS` are in csv with no space |
> | `man mount` | See mount options details |
> | `man FILESYSTEM` | See mount options of the filesystem |
>
> * Mount options can be `ro`, `rw`, `noexec`, `nosuid`, `remount`
> * `nosuid` disables commands running in sudo mode without sudo permissions
> * `remount` allows to mount the filesystem again with new options
> * There are some filesystem specific mount options that we can see by `man FILESYSTEM` and the `remount` option might not work while specifying these options
> * We can write the `MOUNT_OPTIONS` in `/etc/fstab` just like we did here

## REMOTE FILESYSTEMS

| COMMAND | EFFECT |
| ------- | ------ |
| `apt install nfs-kernel-server` | Install NFS server on server |
| `exportfs -r -v` | After editing `/etc/exports` apply changes to the NFS daemon |
| `apt install nfs-common` | Install NFS tools on client |
| `mount HOSTNAME_IP_DOMAINNAME:PATH_TO_REMOTE_DIRECTORY MOUNT_POINT` | Mount a remote directory on a local directory |
| `umount MOUNT_POINT` | Unmount NFS share |

> [!IMPORTANT]
> ### SHARING DIRECTORIES
> * We need to tell the NFS server about the directories that need to be shared
> * We do it by editing `/etc/exports`
> * All entries in it are in the format `DIRECTORY_PATH CIDR_HOSTNAME_IP_DOMAINNAME(EXPORT_OPTIONS)`
>     - `DIRECTORY_PATH` is the path that we want to share
>     - `CIDR_HOSTNAME_IP_DOMAINNAME` this allows to define who can access the data in either of the format
>     - `EXPORT_OPTIONS` defines the properties of the shared directory that need to followed to control the access, some important properties are
>         - `rw`, `ro` - to define read only or read write access
>         - `rsync`, `async` fro asynchronous writes (fast but does not guarantee writes in worst situations), `sync` for synchronous writes (slow but guaranteed the write option)
>         - `no_root_squash` allows root user on NFS client to have root privilages on a remote NFS share they mount, by default NFS squashes root privilages (do not allow to be root on the NFS server shared directory)
>         - `no_subterr_check` no checking for existing files and directories, increases speed but at cost of verification
> * Example entry : `/home/huhu slender_raspi_0(rw,sync,no_subterr_check,no_root_squash) slender_raspi_1(ro,sync,no_root_squash)`
> * Wildcard example entry : `/home/huhu *.example.com(ro,sync)` this allows all computers to access the share which end with `.example.com` this happens due to regex expression
> * To share with everyone, use `*` in `CIDR_HOSTNAME_IP_DOMAINNAME` instead of IP or CIDR or domain or hostname
>
> * We can create this mount come alive automatically every time the computer boots up by editing the `/etc/fstab`
> * The syntax for this would be `HOSTNAME_IP_DOMAINNAME:/PATH_TO_REMOTE_DIRECTORY MOUNT_POINT nfs defaults 0 0`

## NETWORK BLOCK DEVICES
* This is used to access a block device that is connected to a different system on the same network

| COMMAND | EFFECT |
| ------- | ------ |
| `apt install nbd-server` | Install NBD server package on server |
| `systemctl restart nbd-server.service` | Restart NBD server |
| `man 5 nbd-server` | Get halp with nbd-server config file |
| `sudo modprobe nbd` | Load NBD module from kernel |
| `apt install nbd-client` | Install NBD client on client |
| `nbd-client -l NBD_SERVER_IP_HOSTNAME` | See a list of exports available at a NBD server |
| `nbd-client NBD_SERVER_IP_HOSTNAME -N EXPORT_IDENTIFIER` | Connect to NBD server and access the devices using `EXPORT_IDENTIFIER` |
| `nbd-client -d /dev/nbdN` | Disconnect from a NBD device |

> [!TIP]
> ### SHARING DEVICES
> * To share the devices, we need to change the configuration file `/etc/nbd-server/config`
> * We need to change the user and group to get nbd to get read and write permissions, but the same effect can be achieved by removing the lines that defines the user and group
> * Next we have ato add a line with same indentation as `allowlist = true` which allows NBD clients to list what the server or exports has available
> * Now to define what devices can be exported we need to add the following at the end of the script
> 
> ```
> [EXPORT_IDENTIFIER]
>     exportname=/dev/PARTITION_NAME
> ```
> * Example
> ```
> [HUHU]
>     exportname=/dev/PARTITION_NAME
> ```
> 
> * After changing the file `/etc/nbd-server/config` we need to restart the NBD server

> [!TIP]
> ### CONFIGURE and USE CLIENT
> * Install NBD client
> * Load kernel module for NBD
> * The load can be automated by adding an entry in `/etc/modules-load.d/modules.conf`, goto end of file and enter the following text `nbd`
> * Connect To NBD server using the `EXPORT_IDENTIFIER`
> * This gives debug message telling that `/dev/nbdN` device is connected, now we can use this device
> * After completion task, disconnect the device

## LVM SETUP and MANAGEMENT
* LVM is the technology that allows to create one partition logically using 2 or more free space partitions on the same disk by joining them logically and representing them as one.
* All logical volumes are found at `/dev/GROUP_NAME/PARTITION_NAME`

| COMMAND | EFFECT |
| ------- | ------ |
| `apt install lvm2` | Install LVM utilities |
| `lvmdiskscan` | Scan disks and partitions and see what we can operate on |
| `pvs` | See logical volumes |
| `pvcreate /dev/PARTITION_NAME /dev/PARTITION_NAME` | Add physical disk/partition as physical volume to LVM |
| `pvremove /dev/PARTITION_NAME` | rRemove already added physical volumes from LVM |
| `vgcreate GROUP_NAME PV1 PV2 ... PVN` | Create a volume group using PV |
| `vgextend GROUP_NAME /dev/PARTITION_NAME` | Extend the volume group |
| `vgreduce GROUP_NAME /dev/PARTITION_NAME` | Remove a logical volume from a volum group |
| `lvcreate --size NG --name PARTITION_NAME GROUP_NAME` | Create a partition on volume group with size `N` GB and name it `PARTITION_NAME` |
| `lvresize --extents 100%VG GROUP_NAME/PARTITION_NAME` | Extend the partition and use 100 percent of the remaining free space |
| `lvresize --size NG GROUP_NAME/PARTITION_NAME` | Resize the partition in logical volume to given size |
| `lvdisplay` | See all thelogical volumes with all the details |
| `mkfs.ext4 /dev/GROUP_NAME/PARTITION_NAME` | Create a ext4 filesystem on the logical volume |
| `lvresize --resizefs --size NG GROUP_NAME/PARTITION_NAME` | Extend the fs along with logical volume |
| `lvremove GROUP_NAME/PARTITION_NAME` | Remove/delete a logical partition |

> [!IMPORTANT]
> * There are 4 units in LVM:
>     - Physical volume
>     - Logical volume
>     - Volume group
>     - Physical Extent

> [!TIP]
> ### HOW TO CREATE and USE
> * See available disks and partitions using `lvmdiskscan`
> * Create logical volumes
> * Create a volume group with multiple logical volumes and then these will work as they were a single unit

> [!TIP]
> ### EXTEND A VOLUME GROUP
> * Create a new logical volume
> * Extend the volume group

> [!TIP]
> ### CREATE A PARTITION IN VOLUME GROUP
> * The volume group need to have partitions called physical volume
> * Create then using the `lvcreate` command
> * Extend the partition without caring about breaks in continuity in the physical disk
> * Resize the partition if needed

> [!TIP]
> ### FORMATTING A VOLUME
> * By default all these volumes are just spaces, but they are not useful until we create a filesystem on them
> * Create the filesystem using `mkfs.ext4` like commands

> [!TIP]
> ### RESIZE LOGICAL VOLUME WITH FILESYSTEM
> * When we normally run the `lvresize` command on the it extends the volume but the filesystem does remaint the same as before as it was not notified
> * So solve this issue, we pass the `--resizefs` argument

## STORAGE MONITORING

| COMMAND | EFFECT |
| ------- | ------ |
| `apt install sysstat` | Install sysstat monitoring tool |
| `iostat -h` | See disk usage from the point it booted, shows read write load on disks |
| `iostat -h N` | Run iostat in a manner that it refreshes every N seconds |
| `iostat -h N ALL` | See all devices |
| `iostat -h N DEVICE_NAME` | See particular device |
| `pidstat -d` | Shows how processes are utilising the disks |
| `pidstat -d N` | N second average live stats for processes |
| `time dd if=/dev/zero of=DELETEME bs=1 count=1000 oflag=dsync` | stress write test by writing 1MB 1000 times with caching off by using oflag parameter |
| `dmsetup info /dev/dm-0 && lsblk` | See where the `dm-0` device is mapped we get the label ad location by analyzing the result of both commands |

* The `dm-0` device the device that is responsible for mapping devices, ir stands for `device mapper` and it is created by logical volume manager, we can see where it is mapped by using `dmsetup`


## ADVANCED FILE PERMISSIONS
* Normally we can define access for owner, group and other users
* But in some cases we also need to define permissions for multiple users and groups, this is done through ACL (Access Control List)

| COMMAND | EFFECT |
| ------- | ------ |
| `apt install acl` | Install the acl package |
| `setfacl --modify user:USER_NAME:PERMISSIONS FILE_DIRECTORY_PATH` | Change permissions for user for a path |
| `setfacl --modify group:GROUP:PERMISSIONS FILE_DIRECTORY_PATH` | Set ACL permissions for groups |
| `ls -l` | If there is a `+` in permission of a file, an ACL exist for it |
| `getfacl FILE_DIRECTORY_PATH` | See ACL for a path, the mask value is the max value of permissions that the file or directory can have |
| `setfacl --modify mask:PERMISSIONS FILE_DIRECTORY_PATH` | This defines effective real permissions, even if we provide `w` permission in normal ACL but mask have only `r` the user wont be able to write as mask limits the permissions |
| `setfacl --remove-all FILE_DIRECTORY_PATH` | Remove all ACL entries for the path |
| `setfacl --remove-all --recursive DIRECTORY_PATH` | Apply changes to sub-directory items |

* Possible permissions are:
    - `r--`
    - `rw-`
    - `r-x`
    - `-w-`
    - `-wx`
    - `--x`
    - `rwx`

## FILE AND DIRECTORY ATTRIBUTES
* Attributes define file behaviour
* `a` is for append only, this makes file so that only content can be added, no changes allowed in already saved data
* `i` is for immutable, this makes the file frozen, not even a sudo user can change the file i any way (can't delete, modify, rename, etc)

| COMMAND | EFFECT |
| ------- | ------ |
| `chattr +ATTRIBUTE FILE_DIRECTORY_PATH` | Add an attribute |
| `chattr -ATTRIBUTE FILE_DIRECTORY_PATH` | Remove an attribute |
| `lsattr FILE_DIRECTORY_PATH` | See attributes |
| `man chattr` | See docs and other attributes |
















































## VIRTUAL MACHINES
* Install `virsh` a cli tool to manage virtual machines
* Install `virt-manager` `apt install virt-manager`
* Now vreate a configuration file with `.xml` extension, let it be `huhu.xml` and put the following content in it
```
<domain type="qemu">
    <name>TEST</name>
    <memory unit="GiB">1</memory>
    <vcpu>1</vcpu>
    <os>
        <type arch="x86_64">hvm</type>
    </os>
</domain>
```
* `virish define huhu.xml` to create a virtual machine
* `virsh list` to list running virtual machines
* `virsh list --all` to list all virtual machines
* `virsh start MACHINE_NAME` to start the machine
* `virsh reboot MACHINE_NAME` to reboot the machine
* `virsh reset MACHINE_NAME` to reset the machine
* `virsh shutdown MACHINE_NAME` to gracefully shut the machine
* `virsh destroy MACHINE_NAME` to forcefully shut the virtual machine
* `virsh autostart MACHINE_NAME` to enable autostarting the machine
* `virsh autostart --disable MACHINE_NAME` to disable autostart the machine
* `virsh dominfo MACHINE_NAME` to get domain info about the machine
* `virsh setvcpus MACHINE_NAME N --config --maximum` to change allcated vcpus to machine
* `virsh setmaxmem MACHINE_NAME 2048M --config` change maximum memory limit
* `virsh setmem MACHINE_NAME 2048M --config` change memory allocated to machine

### INSTALLING OS IN VIRTUAL MACHINE
* Install minimal image of ubuntu from a url looking similar to `cloud-images.ubuntu.com/minimal/releases/noble/release`
* To download image `wget http://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64.img`
* To download checksum `wget http://cloud-images.ubuntu.com/minimal/releases/noble/release/SHA256SUMS`
* To check if the file was downloaded correctly `sha256sum -c SHA256SUMS 2>&1 | grep OK`
* To see info regarding the image `qemo-img info IMAGE_PATH`
* Virtual size of the disk is the `disk size` that will be configured in the virtual machine while we install the os in the virtual machine
* To change the `disk size` run `qemu-img resize IMAGE_PATH 10G`
* There is a storage pool where all snapshots of machines and other data related to them will be stored, by default these are `/var/lib/libvirt/`
* Copy the image into the pool directory `sudo IMAGE_PATH /var/lib/libvirt/images/`
* Run `virt-install --osinfo list` to get list of type of os to select
* To create a virtual machine `virt-install --osinfo ubuntu24.04 --name NAME --memory 1024 --vcpus 1 --import --disk /var/lib/libvirt/images/IMAGE_NAME --graphics none`
* To get root password add these parematers in the command above `--cloud-init root-password-generate=on`
* We can again connect to the virtual machine after exiting by `virsh console ubuntu1`
* To autodetect OS info in the `--osinfo` parameter we can pass `detect=on`

## MANAGING VIRTUAL and ISOLATED NETWORKS

* If we consider docker containers and docker host and a wifi/ethernet connection, the docker host and docker container have their own routing table, arp table and network interfaces
* The virtual network is like an interface to the localhost but like a switch to the network namespaces
* This is what docker does to manage virtual networks

* `ip -n red link del veth-red`, when we delete one end of the cable, other gets deleted as well as they are in a pair

> [!TIP]
> ### VIRTUAL NAMESPACE HANDS ON
> * Create two network namespaces `ip netns add red && ip netns add blue`
> * Then list them `ip netns`
> * On the host we can see the network interfaces using `ip link`, to see network interfaces on the network namespaces `ip netns exec red ip link` and for blue `ip netns exec blue ip link` or use `ip -n NETWORK_NAMESPACE link`
> * We can note that ew have prevented the nwtwork interface from seeing host interfaces
> * We run `arp` to see host ARP table, to see it on network namespaces run `ip netns exec red arp` and for blue `ip netns exec blue arp`, we note that ARP table lists some entries but no entries insode the network namespaces
> * Right now these network devices are totally isolated and do not have connectivity
> * To connect these networks we need a virtual cable, we create it using `ip link add veth-red type type veth peer name veth-blue`
> * Now we need to plug in these cables `ip link set veth-red netns red` and `ip link set veth-blue netns blue` to create interfaces in those network namespaces
> * Only connecting them is not enough, we need to assign IP to them `ip -n red addr add 192.168.15.1 dev veth-red` and `ip -n red addr add 192.168.15.2 dev veth-blue`
> * Now we need to turn up the links `ip -n red link set veth-red up` and `ip -n blue link set veth-red up`
> * This is the momment when these two can interact with each other, check using `ip netns exec red ping 192.168.15.2` and `ip netns blue ping 192.168.15.1`
> * These network namespaces not have their own ARP table entries for each other

> [!TIP]
> ### VIRTUAL NETWORK HANDS ON
> * We now want to have a virtual network of multiple namespaces, for this we need a virtual switch and for this we have 2 options `Linux Bridge` and `OpenvSwitch`, we will use the first one
> * `ip link add v-net-0 type bridge` creates a virtual bridge network, for the host it is just an interface, we can see it using `ip link`
> * Bring the virtual network up `ip link set dev v-net-0 up`
> * For the namespaces, this network is like a switch to which they can connect
> * Create cables for network interfaces `ip link add veth-red type veth peer name veth-red-br` and `ip link add veth-blue type veth peer name veth-blue-br`
> * Plugin the cable ends one to network namespace and other end to virtual network switch for both the devices
>     - `ip link set veth-red netns red && ip link set veth-red-br master v-net-0` plugs cables red network namespace
>     - `ip link set veth-blue netns blue && ip link set veth-blue-br master v-net-0` plugs cables for blue network namespace
> * Now we need to assign ip addresses to both of the network namespaces
>     - `ip -n red addr add 192.168.15.1 dev veth-red` set ip for red
>     - `ip -n blue addr add 192.168.15.2 dev veth-blue` set ip for blue
> * Now we need to set the interface up on both of them
    - `ip -n link set veth-red up` for red network namespace
    - `ip -n link set veth-blue up`

> [!TIP]
> ### INTERFACING HOST NETWORK AND VIRTUAL NETWORKS
> * What we have setup above using virtual network switch is unreachable from host network
> * For that we need to add ip address to the virtual network `ip addr add 192.168.15.5/24 dev v-net-0`
> * Now we can ping the ip addresses `192.168.15.1` and `192.168.15.2` from the host
>
> * Note that this whole private network is just accessable and contained within the host, we can't access it using outer computer and they also can't access internet
> * It is the host which has the network namespaces and route table entry to reach outside machines and internet, and not the private networks and namespaces, we can chech them using
>     - `ip netns exec blue route`
>     - `ip netns exec red route`
> * Suppose out host have IP address `192.168.1.1` and there is another computer on the network with IP `192.168.1.3`
> * Our localhost also have interfaces to attach to virtual networks and to connect to private actual network, so our localhost is the gateway that connects those virtual nwtworks and the actual private network
> * We can add an route table entry in namespace to route all the traffic to `192.168.1.1` network through the gateway `192.168.15.5`
>     - `ip netns exec blue ip route add 192.168.1.0/24 via 192.168.15.5`
>     - `ip netns exec red ip route add 192.168.1.0.24 via 192.168.15.5`
> * Now these namespace can reach to the private actual network but the request from outside can't reach these namespaces, which means that we can send requests to external networks and machine but we won't get any responce back
> * To make this possible we need to enable NAT on the localhost system
    - `iptables -t nat -A POSTROUTING -s 192.168.15.0/24 -j MASQUERADE`
> * Now we can reach the outer private network, chech `ip netns exec blue ping 192.168.1.3`
>
> * But still we can't reach the internet
> * We need to see routing table `ip netns exec blue route` and `ip netns exec red route`, we see that we have only entries for the networks `192.168.1.0/24` and `192.168.15.0/24` but we do not have any entry that tells how to route to rest of the ip addedss request and network address requests, we need to add the default gateway
> * To add the default gateway, we know that all the routing entries for external network is present in localhost so we add entries in all the network namespaces as
    - `ip netns exec blue ip route add default via 192.168.15.5`
    - `ip netns exec red ip route add default via 192.168.15.5`
> * We are routing default requests through `192.168.15.5` because it is the only way to reach the localhost from the network namespaces
> * Now we can connect to internet, check `ip netns exec blue ping 8.8.8.8` and `ip netns exec red ping 8.8.8.8`
>
> * Still the ip address `192.168.1.3` the private network IP address cant reach the network namespaces because it does not know if it exists or how to reach it, solution to this can be to tell that host how to reach the network namespaces
    - `ip route add 192.168.15.0/24 via 192.168.1.1` running this command on `192.168.1.3` will allow it to reach the network namespaces
> * Or we can add a port forwarding rule to localhost
    - `iptables -t nat -A PREROUTING --dport 80 --to-destination 192.168.15.2:80 -j DNAT`
>
> * Still computers on internet can not access it, to make it do so
    - Set default gateway for the CIDR of virtual network in your home/institution router and add tell it to route through our localhost
    - 
