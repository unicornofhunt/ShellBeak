#!/bin/bash


if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    builtin printf '[!] Bash 4.4 or newer is required.\n' >&2
    exit 1
fi

section() {
    local separator='============================================================'
    builtin printf '\n\033[1;36m%s\n[+] %s\n%s\033[0m\n' \
        "$separator" "$1" "$separator"
}

_print_secret_line() {
    local LC_ALL=C
    local text="$1" lower keyword prefix position first length

    # Preserve the full line while escaping terminal control characters.
    builtin printf -v text '%q' "$text"

    while [[ -n "$text" ]]; do
        lower=${text,,}
        first=${#text} length=0
        for keyword in password token secret api_key -----begin; do
            [[ "$lower" == *"$keyword"* ]] || continue
            prefix=${lower%%"$keyword"*}
            position=${#prefix}
            if (( position < first )); then
                first=$position length=${#keyword}
            fi
        done
        if (( length == 0 )); then
            builtin printf '%s' "$text"
            break
        fi
        builtin printf '%s\033[31m%s\033[0m' \
            "${text:0:first}" "${text:first:length}"
        text=${text:first+length}
    done
    builtin printf '\n'
}

_walk_secret_candidates() {
    local directory="$1"
    local file name line sample line_number
    local previous older matched last_printed context_until
    local scanned_chars

    # Account home directories can also point into virtual/runtime trees.
    case "${directory%/}/" in /proc/*|/sys/*|/dev/*|/run/*) return 0 ;; esac

    [[ ! -L "$directory" &&
       -d "$directory" &&
       -r "$directory" &&
       -x "$directory" ]] || return 0

    # A requested root may already have been reached during recursion.
    if [[ -n ${secret_roots["$directory"]+yes} ]]; then
        [[ ${secret_roots["$directory"]} == scanned ]] && return 0
        secret_roots["$directory"]=scanned
    fi

    # Include ordinary and hidden entries.
    for file in "${directory%/}"/* \
                "${directory%/}"/.[!.]* \
                "${directory%/}"/..?*; do

        [[ -L "$file" ]] && continue

        name=${file##*/}
        case "${name,,}" in
            *.log|*.gz|node_modules|vendor) continue ;;
        esac

        if [[ -d "$file" ]]; then
            _walk_secret_candidates "$file"
            continue
        fi

        [[ -f "$file" && -r "$file" ]] || continue

        # Avoid our output files and the scanner's own source.
        [[ "$file" -ef /dev/fd/1 || "$file" -ef /dev/fd/2 ||
           "$file" -ef "${BASH_SOURCE[0]}" ]] && continue

        # Skip files containing a NUL byte in the first 4096 bytes.
        if IFS= builtin read -r -d '' -n 4096 sample \
            2>/dev/null < "$file"; then
            (( ${#sample} < 4096 )) && continue
        fi

        line_number=0 scanned_chars=0
        last_printed=0 context_until=0
        previous='' older=''

        while IFS= builtin read -r -n 65537 line || [[ -n "$line" ]]; do
            (( line_number += 1 ))
            (( scanned_chars += ${#line} + 1 ))
            if (( ${#line} > 65536 || scanned_chars > 4194304 )); then
                builtin printf '[!] %q: secret scan stopped at line %s (64 KiB line / 4 MiB text budget); remaining content not checked.\n' \
                    "$file" "$line_number"
                (( secret_limited += 1 ))
                break
            fi
            matched=no

            case "${line,,}" in
                *password*|*token*|*secret*|*api_key*|*-----begin*)
                    matched=yes
                    (( matches += 1 ))

                    if (( last_printed == 0 )); then
                        builtin printf '\n\033[36m[+] FILE: %q\033[0m\n' "$file"
                        builtin printf '%s\n' \
                            '------------------------------------------------------------'
                    elif (( line_number - 2 > last_printed + 1 )); then
                        builtin printf '         ...\n'
                    fi

                    # Print preceding lines only if not already displayed.
                    if (( line_number > 2 &&
                          line_number - 2 > last_printed )); then
                        builtin printf '  %6d | ' "$((line_number - 2))"
                        _print_secret_line "$older"
                    fi

                    if (( line_number > 1 &&
                          line_number - 1 > last_printed )); then
                        builtin printf '  %6d | ' "$((line_number - 1))"
                        _print_secret_line "$previous"
                    fi

                    # Include every match and its next two lines.
                    context_until=$((line_number + 2))
                    ;;
            esac

            if (( line_number <= context_until )); then
                if [[ "$matched" == yes ]]; then
                    builtin printf '> %6d | ' "$line_number"
                    _print_secret_line "$line"
                    (( shown += 1 ))
                else
                    builtin printf '  %6d | ' "$line_number"
                    _print_secret_line "$line"
                fi

                last_printed=$line_number
            fi

            # Keep only the previous two lines.
            older=$previous
            previous=$line
        done 2>/dev/null < "$file"

    done

    return 0
}

enum_secret_candidates() {
    local LC_ALL=C
    local directory
    local name password uid gid gecos home_dir shell
    local -a directories=(
        /home /opt /etc /var/backups /var/www /tmp /srv
        /root "${HOME:-}"
    )
    local -A secret_roots=()

    # These locals are also visible to the recursive helper.
    local matches=0 shown=0 secret_limited=0

    # Include custom homes from local accounts.
    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        [[ "$home_dir" == /* && "$home_dir" != / ]] || continue
        directories+=("$home_dir")
    done 2>/dev/null < /etc/passwd

    # Register roots so overlapping scans do not repeat their findings.
    for directory in "${directories[@]}"; do
        directory=${directory%/}
        [[ "$directory" == /* ]] || continue
        secret_roots["$directory"]=pending
    done

    section 'Secret candidates'

    for directory in "${directories[@]}"; do
        directory=${directory%/}
        [[ "$directory" == /* ]] || continue
        _walk_secret_candidates "$directory"
    done

    builtin printf '[+] Matching lines: %s (displayed: %s)\n' \
        "$matches" "$shown"

    if (( secret_limited > 0 )); then
        builtin printf '[!] %s files reached a scan limit; matching-line totals cover only scanned content.\n' "$secret_limited"
    fi

    return 0
}

enum_opt() {
    local directory="${1:-/opt}"
    local file type access
    local listed=0 omitted=0

    [[ -d "$directory" &&
       -r "$directory" &&
       -x "$directory" ]] || return 0

    for file in "${directory%/}"/* \
                "${directory%/}"/.[!.]* \
                "${directory%/}"/..?*; do

        [[ -e "$file" || -L "$file" ]] || continue

        # List symlinks without following their targets.
        if [[ -L "$file" ]]; then
            if (( listed < 20 )); then
                builtin printf '%-7s %-6s %q\n' link n/a "$file"
                (( listed += 1 ))
            else
                (( omitted += 1 ))
            fi
            continue
        fi

        if [[ -d "$file" ]]; then
            type=dir
        elif [[ -f "$file" ]]; then
            type=file
        else
            type=other
        fi

        access=''
        [[ -r "$file" ]] && access+='r' || access+='-'
        [[ -w "$file" ]] && access+='w' || access+='-'
        [[ -x "$file" ]] && access+='x' || access+='-'

        if (( listed < 20 )); then
            builtin printf '%-7s %-6s %q\n' "$type" "$access" "$file"
            (( listed += 1 ))
        else
            (( omitted += 1 ))
        fi

        if [[ "$type" == dir ]]; then
            enum_opt "$file"
        fi
    done
    if (( omitted > 0 )); then
        builtin printf '[!] %q: %s additional entries omitted; subdirectories still traversed.\n' "$directory" "$omitted"
    fi
    return 0
}

walk_file_access() {
    local directory="$1"
    local file type owner executable sticky interesting
    local shown_here=0 matched_here=0

    # Keep virtual/runtime trees out of the generic permissions walk.
    case "${directory%/}/" in
        /proc/*|/sys/*|/dev/*|/run/*|/snap/*) return 0 ;;
    esac

    [[ ! -L "$directory" &&
       -d "$directory" &&
       -r "$directory" &&
       -x "$directory" ]] || return 0

    # Include ordinary and hidden entries.
    for file in "${directory%/}"/* \
                "${directory%/}"/.[!.]* \
                "${directory%/}"/..?*; do

        [[ -L "$file" ]] && continue

        case "$file" in /proc|/sys|/dev|/run|/snap) continue ;; esac
        [[ -f "$file" || -d "$file" ]] || continue

        interesting=no
        if [[ -w "$file" ]]; then
            if [[ ! -O "$file" ]]; then
                interesting=yes
            else
                # Keep writable system/application paths even when we own them.
                case "$file" in
                    /etc/*|/usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|\
                    /opt/*|/srv/*|/var/www/*|/var/spool/cron/*)
                        interesting=yes ;;
                esac
            fi
        fi
        [[ -d "$file" && ! -x "$file" ]] && interesting=no

        if [[ "$interesting" == yes ]]; then
            (( access_total += 1, matched_here += 1 ))
            if (( shown_here < 5 )); then
                type=file owner=other executable=no sticky=no
                [[ -d "$file" ]] && type=dir
                [[ -O "$file" ]] && owner=self
                [[ -x "$file" ]] && executable=yes
                [[ -k "$file" ]] && sticky=yes
                builtin printf '[WRITABLE] TYPE=%s X=%s OWNER=%s STICKY=%s PATH=%q\n' \
                    "$type" "$executable" "$owner" "$sticky" "$file"
                (( shown_here += 1, access_shown += 1 ))
            fi
        fi

        [[ -d "$file" ]] && walk_file_access "$file"
    done
    if (( matched_here > shown_here )); then
        builtin printf '[!] %q: %s additional writable entries omitted.\n' \
            "$directory" "$((matched_here - shown_here))"
    fi
    return 0
}

enum_writable_paths() {
    local remaining="${PATH-}" directory sticky
    local -a directories=(/etc /etc/sudoers.d /etc/cron.d /etc/init.d
        /etc/systemd/system /run/systemd/system /usr/lib/systemd/system
        /usr/local/bin /usr/local/sbin /opt /srv /var/www
        /var/spool/cron /var/spool/cron/crontabs)
    local -A seen=()

    # Empty PATH components mean the current directory.
    while :; do
        directory=${remaining%%:*}
        directories+=("${directory:-.}")
        [[ "$remaining" == *:* ]] || break
        remaining=${remaining#*:}
    done

    builtin printf '\n\033[36m[+] Writable PATH/configuration directories:\033[0m\n'
    for directory in "${directories[@]}"; do
        [[ -d "$directory" && -w "$directory" && -x "$directory" ]] || continue
        directory=${directory%/}/
        [[ -n ${seen["$directory"]+yes} ]] && continue
        seen["$directory"]=1
        sticky=no
        [[ -k "$directory" ]] && sticky=yes
        builtin printf '[WRITABLE DIR] STICKY=%s PATH=%q\n' "$sticky" "$directory"
    done
}

enum_file_access() {
    local start_dir="${1:-/}"
    # Shared with the recursive walker; output limits do not stop traversal.
    local access_total=0 access_shown=0

    if (( EUID == 0 )); then
        builtin printf '[!] Running as root; skipping broad current-user writability enumeration.\n'
        return 0
    fi

    enum_writable_paths
    builtin printf '\n\033[36m[+] Interesting writable files/directories (X means execution or directory traversal):\033[0m\n'
    walk_file_access "$start_dir"
    builtin printf '[+] Displayed %s of %s matching entries.\n' "$access_shown" "$access_total"
    if (( access_total > access_shown )); then
        builtin printf '[!] Showing up to 5 writable entries per directory; omissions are reported for each directory.\n'
    fi
    builtin printf '\n\n'
}

enum_gtfobins() {
    local file=${1:-gtfobins.txt}
    local bin

    if [[ ! -f $file || ! -r $file ]]; then
        builtin printf '[-] Cannot read GTFOBins list: %s\n' "$file" >&2
        return 1
    fi

    # Clear cached paths so type checks the current PATH.
    builtin hash -r 2>/dev/null || :

    section 'GTFOBins'

    while IFS= builtin read -r bin || [[ -n $bin ]]; do
        bin=${bin%$'\r'}  # Accept Windows line endings.
        [[ -n $bin ]] || continue

        if builtin type -P -- "$bin" >/dev/null 2>&1; then
            builtin printf '[+] %s is available, ' "$bin"
            builtin type -P -- "$bin"
        fi
    done < "$file"

    return 0
}

enum_dpkg_packages() {
    local file=/var/lib/dpkg/status
    local line
    local package='' version='' arch='' status=''

    [[ -f "$file" && -r "$file" ]] || return 0

    builtin printf '\n\033[36m[+] Installed Debian packages:\033[0m\n'
    builtin printf '%-40s %-25s %s\n' PACKAGE VERSION ARCH

    while IFS= builtin read -r line || [[ -n "$line" ]]; do
        case "$line" in
            'Package: '*)      package=${line#Package: } ;;
            'Version: '*)      version=${line#Version: } ;;
            'Architecture: '*) arch=${line#Architecture: } ;;
            'Status: '*)       status=${line#Status: } ;;

            '')
                # Blank lines separate package records.
                if [[ -n "$package" && "${status##* }" == installed ]]; then
                    builtin printf '%-40s %-25s %s\n' \
                        "$package" "$version" "$arch"
                fi

                package='' version='' arch='' status=''
                ;;
        esac
    done 2>/dev/null < "$file"

    # Handle a final record without a trailing blank line.
    if [[ -n "$package" && "${status##* }" == installed ]]; then
        builtin printf '%-40s %-25s %s\n' \
            "$package" "$version" "$arch"
    fi
}

enum_pacman_packages() {
    local file line package version arch

    [[ -d /var/lib/pacman/local ]] || return 0

    builtin printf '\n\033[36m[+] Installed pacman packages:\033[0m\n'
    builtin printf '%-40s %-25s %s\n' PACKAGE VERSION ARCH

    for file in /var/lib/pacman/local/*/desc; do
        [[ -f "$file" && -r "$file" ]] || continue

        package='' version='' arch=''

        # Each field marker is followed by its value.
        while IFS= builtin read -r line || [[ -n "$line" ]]; do
            case "$line" in
                '%NAME%')    IFS= builtin read -r package || : ;;
                '%VERSION%') IFS= builtin read -r version || : ;;
                '%ARCH%')    IFS= builtin read -r arch || : ;;
            esac
        done 2>/dev/null < "$file"

        [[ -n "$package" ]] || continue

        builtin printf '%-40s %-25s %s\n' \
            "$package" "$version" "$arch"
    done
}

enum_apk_packages() {
    local file=/lib/apk/db/installed
    local line prefix
    local package='' version='' arch=''

    # This reader supports the text database only.
    if [[ -f /lib/apk/db/installed.adb ]]; then
        builtin printf '\n[!] Binary APK database found; reader not implemented\n'
        return 0
    fi

    [[ -f "$file" && -r "$file" && -s "$file" ]] || return 0

    # Text records start with a field letter and a colon.
    IFS= builtin read -r -N 2 prefix 2>/dev/null < "$file" || return 0

    if [[ "$prefix" != ?: ]]; then
        builtin printf '\n[!] Unrecognized APK database format; skipped\n'
        return 0
    fi

    builtin printf '\n\033[36m[+] Installed APK packages:\033[0m\n'
    builtin printf '%-40s %-25s %s\n' PACKAGE VERSION ARCH

    while IFS= builtin read -r line || [[ -n "$line" ]]; do
        case "$line" in
            P:*) package=${line#P:} ;;
            V:*) version=${line#V:} ;;
            A:*) arch=${line#A:} ;;

            '')
                if [[ -n "$package" ]]; then
                    builtin printf '%-40s %-25s %s\n' \
                        "$package" "$version" "$arch"
                fi

                package='' version='' arch=''
                ;;
        esac
    done 2>/dev/null < "$file"

    # Handle a final record without a trailing blank line.
    if [[ -n "$package" ]]; then
        builtin printf '%-40s %-25s %s\n' \
            "$package" "$version" "$arch"
    fi
}

enum_installed_software() {
    local directory file

    enum_dpkg_packages
    enum_pacman_packages
    enum_apk_packages

    # Recognize common RPM databases without attempting to decode them.
    for directory in /var/lib/rpm /usr/lib/sysimage/rpm; do
        for file in "$directory/rpmdb.sqlite" \
                    "$directory/Packages" \
                    "$directory/Packages.db"; do
            [[ -f "$file" ]] || continue

            builtin printf '\n[!] RPM database found: %q\n' "$file"
            builtin printf '    Enumeration requires a database-aware reader\n'
            case "$file" in
                */rpmdb.sqlite)
                    builtin printf '    SQLite inspection: sqlite3 -readonly %q\n' "$file" ;;
                *)
                    builtin printf '    This is not SQLite; use a reader for this RPM database format.\n' ;;
            esac
            break 2
        done
    done
}

enum_suid() {
    local directory="${1:-/}"
    local entry

    case "${directory%/}/" in /proc/*|/sys/*|/dev/*) return 0 ;; esac
    [[ -L "$directory" ]] && return 0
    [[ -d "$directory" && -r "$directory" && -x "$directory" ]] || return 0

    for entry in "${directory%/}"/* \
                 "${directory%/}"/.[!.]* \
                 "${directory%/}"/..?*; do

        # Skip symbolic links.
        [[ -L "$entry" ]] && continue

        if [[ -d "$entry" ]]; then
            enum_suid "$entry"

        elif [[ -f "$entry" ]]; then
            [[ -u "$entry" ]] && builtin printf '[SUID] %q\n' "$entry"
            [[ -g "$entry" ]] && builtin printf '[SGID] %q\n' "$entry"
        fi
    done
    return 0
}

enum_tcp_listeners() {
    local proc pid fdinfo fd key value name owner
    local table protocol address_hex port address word offset inode
    local -a fields=()
    local -A owners=()

    # Map socket inodes to processes and file descriptors.
    for proc in /proc/[0-9]*; do
        [[ -r "$proc/fdinfo" && -x "$proc/fdinfo" ]] || continue

        pid=${proc##*/}
        name="?"
        IFS= builtin read -r name 2>/dev/null < "$proc/comm" || name="?"

        for fdinfo in "$proc"/fdinfo/[0-9]*; do
            fd=${fdinfo##*/}

            # Confirm that this descriptor refers to a socket.
            [[ -r "$fdinfo" && -S "$proc/fd/$fd" ]] || continue

            while IFS=$' \t' builtin read -r key value; do
                [[ "$key" == ino: && -n "$value" ]] || continue

                builtin printf -v owner 'pid=%s,fd=%s,name=%q' \
                    "$pid" "$fd" "$name"

                owners["$value"]+="${owners["$value"]:+; }$owner"
                break
            done 2>/dev/null < "$fdinfo"
        done
    done

    builtin printf '%-5s %-48s %-7s %s\n' PROTO LOCAL UID PROCESS

    for table in /proc/net/tcp /proc/net/tcp6; do
        [[ -r "$table" ]] || continue

        protocol=TCP4
        [[ "$table" == /proc/net/tcp6 ]] && protocol=TCP6

        while IFS=$' \t' builtin read -r -a fields; do
            (( ${#fields[@]} >= 10 )) || continue
            [[ "${fields[3]}" == 0A ]] || continue  # TCP_LISTEN

            # Zero-based columns: local=1, UID=7, inode=9.
            address_hex=${fields[1]%:*}
            port=$((16#${fields[1]##*:}))
            inode=${fields[9]}

            # Decode addresses as stored on little-endian Linux.
            if [[ "$protocol" == TCP4 ]]; then
                builtin printf -v address '%d.%d.%d.%d' \
                    "$((16#${address_hex:6:2}))" \
                    "$((16#${address_hex:4:2}))" \
                    "$((16#${address_hex:2:2}))" \
                    "$((16#${address_hex:0:2}))"
            else
                address=""

                # Reverse bytes within each 32-bit IPv6 word.
                for ((offset=0; offset<32; offset+=8)); do
                    word=${address_hex:offset:8}
                    address+="${address:+:}${word:6:2}${word:4:2}:${word:2:2}${word:0:2}"
                done

                address="[$address]"
            fi

            builtin printf '%-5s %-48s %-7s %s\n' \
                "$protocol" "$address:$port" "${fields[7]}" \
                "${owners["$inode"]:-[unavailable]}"
        done 2>/dev/null < "$table"
    done
}

enum_network() {
    local interface attribute value file

    # Basic interface details.
    for interface in /sys/class/net/*; do
        [[ -d "$interface" ]] || continue

        builtin printf '\n[+] Interface: %q\n' "${interface##*/}"

        for attribute in address operstate carrier mtu; do
            if IFS= builtin read -r value \
                2>/dev/null < "$interface/$attribute"; then

                builtin printf '  %-10s %s\n' "$attribute" "$value"
            fi
        done
    done

    # Network information in its original text format.
    for file in \
        /proc/net/dev \
        /proc/net/fib_trie \
        /proc/net/route \
        /proc/net/if_inet6 \
        /etc/resolv.conf \
        /etc/nsswitch.conf \
        /run/systemd/resolve/resolv.conf; do

        [[ -r "$file" ]] || continue

        builtin printf '\n[+] Reading %q\n' "$file"
        read_file "$file"
    done
}

enum_git_docker_netrc() {
    local name password uid gid gecos home_dir shell
    local config_file file
    local -a home_dirs=()
    local -A checked_homes=()

    # Collect home directories from local accounts.
    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        [[ "$home_dir" == /* ]] || continue
        home_dirs+=("$home_dir")
    done 2>/dev/null < /etc/passwd

    home_dirs+=("${HOME:-}" /root /home/*)

    for home_dir in "${home_dirs[@]}"; do
        [[ "$home_dir" == /* && -d "$home_dir" ]] || continue

        home_dir=${home_dir%/}/

        [[ -n "${checked_homes["$home_dir"]+yes}" ]] && continue
        checked_homes["$home_dir"]=1

        for config_file in \
            .git-credentials \
            .gitconfig \
            .docker/config.json \
            .netrc; do

            file="${home_dir}${config_file}"

            # Only regular files; skip symlinks.
            [[ -f "$file" && ! -L "$file" ]] || continue

            builtin printf '\n[+] File: %q\n' "$file"

            if [[ -r "$file" ]]; then
                read_file "$file"
            else
                builtin printf '  [!] Not readable\n'
            fi
        done
    done
}

read_cloud_directory() {
    local directory="$1"
    local entry sample
    local LC_ALL=C

    [[ -d "$directory" && ! -L "$directory" ]] || return 0

    if [[ ! -r "$directory" || ! -x "$directory" ]]; then
        builtin printf '\n[!] Cannot access directory: %q\n' "$directory"
        return 0
    fi

    for entry in "$directory"/* \
                 "$directory"/.[!.]* \
                 "$directory"/..?*; do

        [[ -L "$entry" ]] && continue

        if [[ -d "$entry" ]]; then
            read_cloud_directory "$entry"

        elif [[ -f "$entry" ]]; then
            builtin printf '\n[+] Cloud file: %q\n' "$entry"

            if [[ -r "$entry" ]]; then
                [[ "$entry" -ef /dev/fd/1 || "$entry" -ef /dev/fd/2 ]] && continue
                case "${entry,,}" in
                    *.log|*.log.[0-9]*|*/logs/*)
                        builtin printf '  [log content omitted]\n'
                        continue ;;
                esac
                # Show readable text files with the common fixed excerpt limits.
                if IFS= builtin read -r -d '' -n 4096 sample 2>/dev/null < "$entry"; then
                    if (( ${#sample} < 4096 )); then
                        builtin printf '  [binary content omitted]\n'
                        continue
                    fi
                fi
                read_file "$entry"
            else
                builtin printf '  [!] Not readable\n'
            fi
        fi
    done
}

enum_cloud_files() {
    local name password uid gid gecos home_dir shell
    local -a home_dirs=()
    local -A checked_homes=()

    # Collect home directories from local accounts.
    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        [[ "$home_dir" == /* ]] || continue
        home_dirs+=("$home_dir")
    done 2>/dev/null < /etc/passwd

    # Also check common locations.
    home_dirs+=("${HOME:-}" /root /home/*)

    for home_dir in "${home_dirs[@]}"; do
        [[ "$home_dir" == /* && -d "$home_dir" ]] || continue

        home_dir=${home_dir%/}/

        [[ -n "${checked_homes["$home_dir"]+yes}" ]] && continue
        checked_homes["$home_dir"]=1

        read_cloud_directory "${home_dir}.aws"
        read_cloud_directory "${home_dir}.config/gcloud"
        read_cloud_directory "${home_dir}.azure"
    done
}

enum_ssh_files() {
    local name password uid gid gecos home_dir shell
    local ssh_dir file readable
    local -a home_dirs=()
    local -A checked_homes=()

    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        [[ "$home_dir" == /* ]] || continue
        home_dirs+=("$home_dir")
    done 2>/dev/null < /etc/passwd

    home_dirs+=("${HOME:-}" /root /home/*)

    for home_dir in "${home_dirs[@]}"; do
        [[ "$home_dir" == /* && -d "$home_dir" ]] || continue

        home_dir=${home_dir%/}/
        [[ -n "${checked_homes["$home_dir"]+yes}" ]] && continue
        checked_homes["$home_dir"]=1

        ssh_dir="${home_dir}.ssh"
        [[ -d "$ssh_dir" ]] || continue

        builtin printf '\n[+] SSH directory: %q\n' "$ssh_dir"

        if [[ ! -r "$ssh_dir" || ! -x "$ssh_dir" ]]; then
            builtin printf '  [!] Cannot list or access this directory\n'
            continue
        fi

        for file in "$ssh_dir"/* "$ssh_dir"/.[!.]* "$ssh_dir"/..?*; do
            [[ -f "$file" ]] || continue

            readable=no
            [[ -r "$file" ]] && readable=yes

            builtin printf '  READABLE=%-3s FILE=%q\n' "$readable" "$file"
        done
    done
}

enum_shell_startup_files() {
    local name password uid gid gecos home_dir shell
    local startup_name file
    local -a home_dirs=()
    local -A checked_homes=()

    # Collect home directories from all local accounts.
    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        [[ "$home_dir" == /* ]] || continue
        home_dirs+=("$home_dir")
    done 2>/dev/null < /etc/passwd

    home_dirs+=("${HOME:-}" /root /home/*)

    for home_dir in "${home_dirs[@]}"; do
        [[ "$home_dir" == /* && -d "$home_dir" && -x "$home_dir" ]] || continue

        # Avoid checking the same home path twice.
        home_dir=${home_dir%/}/
        [[ -n "${checked_homes["$home_dir"]+yes}" ]] && continue
        checked_homes["$home_dir"]=1

        for startup_name in \
            .profile \
            .bashrc \
            .bash_profile \
            .bash_login \
            .bash_aliases \
            .zshenv \
            .zprofile \
            .zshrc \
            .zlogin \
            .config/fish/config.fish; do

            file="${home_dir}${startup_name}"
            [[ -f "$file" && -r "$file" ]] || continue

            builtin printf '\n[+] Shell startup file: %q\n' "$file"
            read_file "$file"
        done
    done
}

enum_history_files() {
    local name password uid gid gecos home_dir shell
    local history_name file
    local -a home_dirs=()
    local -A checked_homes=()

    # Collect home directories from all local accounts.
    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        [[ "$home_dir" == /* ]] || continue
        home_dirs+=("$home_dir")
    done 2>/dev/null < /etc/passwd

    # Also check common locations, including homes absent from /etc/passwd.
    home_dirs+=("${HOME:-}" /root /home/*)

    for home_dir in "${home_dirs[@]}"; do
        [[ "$home_dir" == /* && -d "$home_dir" && -x "$home_dir" ]] || continue

        # Use one trailing slash and avoid checking the same path twice.
        home_dir=${home_dir%/}/
        [[ -n "${checked_homes["$home_dir"]+yes}" ]] && continue
        checked_homes["$home_dir"]=1

        for history_name in \
            .bash_history \
            .zsh_history \
            .zhistory \
            .sh_history \
            .ash_history \
            .ksh_history \
            .history \
            .local/share/fish/fish_history \
            .config/fish/fish_history; do

            file="${home_dir}${history_name}"
            [[ -f "$file" && -r "$file" ]] || continue

            builtin printf '\n[+] History file: %q\n' "$file"
            read_file "$file"
        done
    done
}

enum_interesting_group_users() {
    local name password uid gid gecos home_dir shell
    local group_name group_password group_gid members
    local matched_groups

    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        [[ -n "$name" && -n "$gid" ]] || continue
        matched_groups=''

        while IFS=: builtin read -r group_name group_password group_gid members; do
            case "$group_name" in
                sudo|wheel|docker|lxd|disk|shadow|video) ;;
                *) continue ;;
            esac

            # Match the primary group or an explicit membership.
            if [[ "$group_gid" == "$gid" ||
                  ",$members," == *",$name,"* ]]; then
                matched_groups+="${matched_groups:+, }$group_name"
            fi
        done 2>/dev/null < /etc/group

        [[ -n "$matched_groups" ]] || continue

        builtin printf '[!] USER=%q UID=%s GROUPS=%s SHELL=%q\n' \
            "$name" "$uid" "$matched_groups" "$shell"
    done 2>/dev/null < /etc/passwd
}

enum_login_users() {
    local name password uid gid gecos home_dir shell
    local group_name group_password group_gid members
    local key value rest uid_min=1000

    # Fall back to 1000 if UID_MIN is missing, invalid or unreadable.
    while IFS=$' \t' builtin read -r key value rest || [[ -n "$key" ]]; do
        [[ "$key" == UID_MIN ]] || continue

        case "$value" in
            ''|*[!0-9]*) continue ;;
        esac

        uid_min=$value
        break
    done 2>/dev/null < /etc/login.defs

    while IFS=: builtin read -r name password uid gid gecos home_dir shell; do
        # Skip missing or malformed UIDs.
        case "$uid" in
            ''|*[!0-9]*) continue ;;
        esac

        (( 10#$uid >= 10#$uid_min )) || continue

        case "${shell##*/}" in
            bash|rbash|zsh|sh|dash|ash|ksh|mksh|fish|csh|tcsh)
                builtin printf '[LOGIN CANDIDATE] USER=%q UID=%s GID=%s HOME=%q SHELL=%q\n' \
                    "$name" "$uid" "$gid" "$home_dir" "$shell"

                builtin printf '  GROUPS:'

                while IFS=: builtin read -r group_name group_password group_gid members; do
                    if [[ "$group_gid" == "$gid" ||
                          ",$members," == *",$name,"* ]]; then
                        builtin printf ' %q(%s)' "$group_name" "$group_gid"
                    fi
                done 2>/dev/null < /etc/group

                builtin printf '\n'
                ;;
        esac
    done 2>/dev/null < /etc/passwd
}

show_task_config() {
    local file="$1" kind="$2"
    local line sample parent writable=no parent_wx=no sticky=no
    local shown_lines=0 line_limit=200 scanned_chars=0
    local LC_ALL=C

    [[ -f "$file" ]] || return 0
    [[ "$file" -ef /dev/fd/1 || "$file" -ef /dev/fd/2 ]] && return 0
    (( EUID == 0 )) && line_limit=80
    [[ -w "$file" ]] && writable=yes
    parent=${file%/*}
    [[ -w "$parent" && -x "$parent" ]] && parent_wx=yes
    [[ -k "$parent" ]] && sticky=yes
    builtin printf '\n[+] FILE=%q ACCESS_EUID=%s WRITABLE=%s PARENT_WX=%s PARENT_STICKY=%s\n' \
        "$file" "$EUID" "$writable" "$parent_wx" "$sticky"
    if [[ ! -r "$file" ]]; then
        builtin printf '  [not readable]\n'
        return 0
    fi

    # Root's writability is not evidence of access by an unprivileged account.
    if [[ "$kind" == script ]] && (( EUID == 0 )); then
        builtin printf '  [script body omitted in root runs; schedule and unit files are still shown]\n'
        return 0
    fi
    if IFS= builtin read -r -d '' -n 4096 sample 2>/dev/null < "$file"; then
        if (( ${#sample} < 4096 )); then
            builtin printf '  [binary content omitted]\n'
            return 0
        fi
    fi

    while IFS= builtin read -r -n 65537 line || [[ -n "$line" ]]; do
        (( scanned_chars += ${#line} + 1 ))
        if (( ${#line} > 65536 || scanned_chars > 4194304 )); then
            builtin printf '  [!] Read limit reached (64 KiB line / 4 MiB text budget); remaining content not checked.\n'
            break
        fi
        # Trim leading indentation only for the comment/blank-line check.
        line=${line#"${line%%[!$' \t']*}"}
        case "$line" in ''|\#*|\;*) continue ;; esac
        if (( shown_lines >= line_limit )); then
            builtin printf '  [!] Further configuration lines omitted (limit: %s).\n' "$line_limit"
            break
        fi
        builtin printf '  %s' "${line:0:2000}"
        (( ${#line} > 2000 )) && builtin printf ' [line excerpt clipped]'
        builtin printf '\n'
        (( shown_lines += 1 ))
    done 2>/dev/null < "$file"
    return 0
}

enum_scheduled_tasks() {
    local file kind

    section 'Cron, anacron and init-script files'
    for file in /etc/crontab /etc/anacrontab /etc/cron.d/* \
                /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
                /var/spool/cron/* /var/spool/cron/crontabs/* /etc/init.d/*; do
        kind=cron
        case "$file" in
            /etc/cron.hourly/*|/etc/cron.daily/*|/etc/cron.weekly/*|/etc/cron.monthly/*|/etc/init.d/*)
                kind=script ;;
        esac
        show_task_config "$file" "$kind"
    done
}

enum_systemd_configs() {
    local directory file

    section 'Systemd service/timer/socket/path files and drop-ins'
    builtin printf '    File inventory only; active state and merged settings are not evaluated.\n'
    for directory in /etc/systemd/system /run/systemd/system \
                     /etc/systemd/system.control /run/systemd/system.control \
                     /run/systemd/transient /run/systemd/generator.early \
                     /run/systemd/generator /run/systemd/generator.late \
                     /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [[ -d "$directory" && -r "$directory" && -x "$directory" ]] || continue
        # Avoid duplicate vendor units on merged-/usr systems.
        [[ "$directory" == /lib/systemd/system &&
           "$directory" -ef /usr/lib/systemd/system ]] && continue
        for file in "$directory"/*.service "$directory"/*.timer \
                    "$directory"/*.socket "$directory"/*.path "$directory"/*.d/*.conf; do
            show_task_config "$file" unit
        done
    done
}

enum_processes() {
    local proc pid key value
    local name state ppid uid euid gid egid
    local threads vmrss capeff nnp seccomp tracer
    local cmdline arg escaped
    local -a argv

    for proc in /proc/[0-9]*; do
        [[ -d "$proc" && -r "$proc/status" ]] || continue

        pid=${proc##*/}

        # Reset variables for each process
        name='' state='' ppid=''
        uid='' euid='' gid='' egid=''
        threads='' vmrss='' capeff=''
        nnp='' seccomp='' tracer=''

        # Parse /proc/PID/status
        while IFS=$'\t' builtin read -r key value; do
            case $key in
                Name:)       name=$value ;;
                State:)      state=$value ;;
                PPid:)       ppid=$value ;;
                Uid:)        builtin read -r uid euid _ <<< "$value" ;;
                Gid:)        builtin read -r gid egid _ <<< "$value" ;;
                Threads:)    threads=$value ;;
                VmRSS:)      vmrss=$value ;;
                CapEff:)     capeff=$value ;;
                NoNewPrivs:) nnp=$value ;;
                Seccomp:)    seccomp=$value ;;
                TracerPid:)  tracer=$value ;;
            esac
        done 2>/dev/null < "$proc/status"

        [[ -n "$name" ]] || continue

        # Read NUL-separated process arguments
        argv=()
        if [[ -r "$proc/cmdline" ]]; then
            builtin mapfile -d '' -t argv 2>/dev/null < "$proc/cmdline"
        fi

        # Construct a shell-escaped representation
        cmdline=''
        for arg in "${argv[@]}"; do
            builtin printf -v escaped '%q' "$arg"
            cmdline+="${cmdline:+ }${escaped}"
        done

        [[ -n "$cmdline" ]] || cmdline='[empty/unavailable]'

        builtin printf 'PID=%s PPID=%s NAME=%q STATE=%s\n' \
            "$pid" "$ppid" "$name" "$state"

        builtin printf '  UID=%s EUID=%s GID=%s EGID=%s THREADS=%s VmRSS=%s\n' \
            "$uid" "$euid" "$gid" "$egid" "$threads" "$vmrss"

        builtin printf '  CapEff=%s NoNewPrivs=%s Seccomp=%s TracerPid=%s\n' \
            "$capeff" "$nnp" "$seccomp" "$tracer"

        builtin printf '  CMD=%s\n\n' "$cmdline"
    done
}

check_proc() {
    local source target filesystem options rest
    local hidepid

    # Listing a directory requires read permission; traversing it requires execute.
    if [[ ! -d /proc || ! -r /proc || ! -x /proc ]]; then
        builtin printf '[!] /proc is missing or inaccessible\n'
        return 1
    fi

    builtin printf '[+] /proc is accessible\n'

    while IFS=' ' builtin read -r source target filesystem options rest; do
        [[ "$target" == /proc && "$filesystem" == proc ]] || continue

        # The default is 0 when hidepid is not specified.
        hidepid=0
        case ",$options," in
            *,hidepid=*)
                hidepid=${options#*hidepid=}
                hidepid=${hidepid%%,*}
                ;;
        esac

        builtin printf '[+] /proc mount options: %s\n' "$options"
        builtin printf '[+] hidepid=%s\n' "$hidepid"
        return 0
    done 2>/dev/null < /proc/self/mounts

    builtin printf '[!] Cannot determine mount options; hidepid is unknown\n'
    return 0
}

enum_identity() {
    local name password id rest group_id

    builtin printf 'UID=%s EUID=%s GROUPS=%s\n' \
        "$UID" "$EUID" "${GROUPS[*]}"

    # Resolve the effective UID to a local username.
    while IFS=: builtin read -r name password id rest; do
        [[ "$id" == "$EUID" ]] || continue
        builtin printf 'USER=%q\n' "$name"
        break
    done 2>/dev/null < /etc/passwd

    # Resolve the current group IDs to local group names.
    while IFS=: builtin read -r name password id rest; do
        for group_id in "${GROUPS[@]}"; do
            [[ "$id" == "$group_id" ]] || continue
            builtin printf 'GROUP=%q GID=%s\n' "$name" "$id"
            break
        done
    done 2>/dev/null < /etc/group
}


read_file() {
    local file="$1"
    local line line_count=0 line_limit=${2:-200}
    local LC_ALL=C

    # The internal limit 0 is reserved for account/mount inventories in main.
    (( EUID == 0 && line_limit > 80 )) && line_limit=80

    # Avoid reading and appending to the same file.
    [[ "$file" -ef /dev/fd/1 || "$file" -ef /dev/fd/2 ]] && return 0
    [[ -f "$file" && -r "$file" ]] || return 0

    while IFS= builtin read -r -n 65537 line || [[ -n "$line" ]]; do
        if (( ${#line} > 65536 )); then
            builtin printf '[!] %q: line %s exceeds 64 KiB; remaining content not read.\n' "$file" "$((line_count + 1))"
            break
        fi
        if (( line_limit > 0 && line_count >= line_limit )); then
            builtin printf '[!] %q: further content omitted (first %s lines shown).\n' "$file" "$line_limit"
            break
        fi
        builtin printf '%s' "${line:0:2000}"
        (( ${#line} > 2000 )) && builtin printf ' [line excerpt clipped]'
        builtin printf '\n'
        (( line_count += 1 ))
    done 2>/dev/null < "$file"
    return 0
}

enum_sudoers() {
    local file

    builtin printf '    Readable policy files only; effective sudo privileges are not evaluated.\n'

    if [[ -d /etc/sudoers.d &&
          ( ! -r /etc/sudoers.d || ! -x /etc/sudoers.d ) ]]; then
        builtin printf '[!] Cannot enumerate /etc/sudoers.d\n'
    fi

    for file in /etc/sudoers \
                /etc/sudoers.d/* \
                /etc/sudoers.d/.[!.]* \
                /etc/sudoers.d/..?*; do

        # Skip the packaged explanatory README, not the actual policy file.
        [[ "$file" == /etc/sudoers.d/README ]] && continue
        [[ -f "$file" ]] || continue

        builtin printf '\n\033[36m[+] Found %q\033[0m\n' "$file"

        if [[ -r "$file" ]]; then
            read_file "$file"
        else
            builtin printf '[!] Not readable\n'
        fi
    done
}

# Main
section 'User info'
enum_identity

section 'Sudoers files'
enum_sudoers

section 'Reading /etc/os-release'
read_file /etc/os-release

section 'Reading /etc/shadow'
read_file /etc/shadow

section 'Reading /etc/issue'
read_file /etc/issue

section 'Reading /etc/passwd'
read_file /etc/passwd 0

section 'Likely local login accounts'
enum_login_users

section 'Reading /etc/group'
read_file /etc/group 0

section 'Users in interesting groups'
enum_interesting_group_users

section 'Environment variables'
builtin export -p

section 'Readable history files'
enum_history_files

section 'Readable shell startup files'
enum_shell_startup_files

section 'SSH files and readability'
enum_ssh_files

section 'Cloud configuration files'
enum_cloud_files

section 'Docker, Git, Netrc files'
enum_git_docker_netrc

section 'Network info'
enum_network

section 'Reading /etc/hosts'
read_file /etc/hosts

section 'SUID/SGID files'
enum_suid / 2>/dev/null

section 'Installed software'
enum_installed_software

section "/opt entries — access for EUID=$EUID"
builtin printf '%-7s %-6s %s\n' TYPE ACCESS PATH
enum_opt /opt 2>/dev/null

section 'Mounts'
read_file /proc/mounts 0

section '/proc availability'
if check_proc; then
    section 'Visible processes'

    enum_processes

    section 'Listening TCP sockets'
    enum_tcp_listeners

    section 'IPv4 neighbors (ARP cache)'
    read_file /proc/net/arp

    section 'Reading /proc/version'
    read_file /proc/version

fi

enum_scheduled_tasks
enum_systemd_configs

enum_gtfobins

section 'File permissions'
enum_file_access / 2>/dev/null

enum_secret_candidates 2>/dev/null
