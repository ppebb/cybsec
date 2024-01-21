# Linux Checklist (WIP)
## Points covered by the script
- System updates
- Enabling of automatic updates
- Firewall configuration
- User management (of existing users)
- Password reassignment of all users
- Password expiry settings in login.defs
- libpam-cracklib configuration
- Root account lock
- Location of media files and user-downloaded packages
- Configuration of kernel parameters in /etc/sysctl.conf
- Removal of malicious or "hacking" software
- Warnings for potentially unwanted software (nginx, apache, etc)
- Location of files containing user passwords
- Listing system units
- Verification of file permissions, location of files with bad permissions such as sticky bits, world-writeable files, or files missing a user and group
- Check for rc_local
- Disabling usb and firewire
- Check for all crontabs
- Rkhunter
- Clamav
- Display manager configuration (both gdm3 and lightdm)
- Auditd
- Integrity checks for user files such as .bashrc or .profile (in ./default_files)
- Installation and configuration of se-linux (do NOT use this on a system with apparmor. This will prevent boot on ubuntu and debian, for example)
- Installation of fail2ban
- Integrity and permissions checks on files hashed by hash.sh (in ./hashes)

## Additional checks
- Search through enabled tasks manually to disable anything extra
- Application security. Use CIS Benchmarks or online configurations for applications running on the system such as nginx or psql
- Configuration of system default browser according to readme. Enable popup blockers and other security settings depending on the browser.
- Make sure you reset all passwords after requiring a more secure hashing algorithm in pam settings
- Check permissions in /etc. Points for fixing permissions there. Compare with other files and whatever is hashed.
- [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) can locate files with improper permissions and whatnot as further backup to the checks existing in the script.
- Ensure services are allowed through the firewall depending on what is required (ssh, ftp, etc)
- Always check for a python or netcat backdoor. See running processes with `ps -e` or `ps -auxf` and open ports with `netstat -tulpn`
- Further manual verification of users. Just in case.
- Check hosts file
- Check apt configuration so updates go through.
- Disable shell login for users that should not have it. Set everything not a user to nologin
- Check ALL autorun files (rc, crontabs, service)
- Consider configuring apparmour
- Consider setting a default umask
```bash
# Check for "weird admins"
mawk -F: '$1 == "sudo"' /etc/group

# Check for any weird users. This just lists out every user
mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd

# Check for empty passwords
mawk -F: '$2 == ""' /etc/passwd

# Check for non-root UID 0 users
mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd
```

## Additional resources I've found which may be useful
[Some checklist google doc](https://docs.google.com/document/d/1Sm8bEZyMhTZeXcWxqq5wF2_e7-zT92IM/edit) that contains useful checks and some application security for a couple things  
[Another checklist google doc](https://docs.google.com/document/d/1NZB-XTPPZlUqQhfowbH0T5Gm6rkSfCb5EMYGE5aVfmY/edit) that might be useful. References some files that I don't have. Oh well.  
[Linux checklist](https://gist.github.com/bobpaw/a0b6828a5cfa31cfe9007b711a36082f) that has some useful application security  
[2020 writeup](https://sourque.com/ctf/hivestorm/hs20/) and [2021 writeup](https://sourque.com/ctf/hivestorm/hs21/) with lots of useful advice for BOTH linux and windows
[sysctl explorer](https://sysctl-explorer.net/)  
[How to disable null passwords](https://www.cyberciti.biz/tips/linux-or-unix-disable-null-passwords.html) in case I have to use fedora lol  
