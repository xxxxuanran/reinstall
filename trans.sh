#!/bin/ash
# shellcheck shell=dash
# shellcheck disable=SC2086,SC3047,SC3036,SC3010,SC3001,SC3060
# alpine 默认使用 busybox ash
# 注意 bash 和 ash 以下语句结果不同
# [[ a = '*a' ]] && echo 1

# 出错后停止运行，将进入到登录界面，防止失联
set -eE

# 用于判断 reinstall.sh 和 trans.sh 是否兼容
# shellcheck disable=SC2034
SCRIPT_VERSION=4BACD833-A585-23BA-6CBB-9AA4E08E0003

TRUE=0
FALSE=1
EFI_UUID=C12A7328-F81F-11D2-BA4B-00A0C93EC93B

error() {
    color='\e[31m'
    plain='\e[0m'
    echo -e "${color}***** ERROR *****${plain}" >&2
    echo -e "${color}$*${plain}" >&2
}

info() {
    color='\e[32m'
    plain='\e[0m'
    local msg

    if [ "$1" = false ]; then
        shift
        msg=$*
    else
        msg=$(echo "$*" | to_upper)
    fi

    echo -e "${color}***** $msg *****${plain}" >&2
}

warn() {
    color='\e[33m'
    plain='\e[0m'
    echo -e "${color}Warning: $*${plain}" >&2
}

error_and_exit() {
    error "$@"
    echo "Run '/trans.sh' to retry." >&2
    echo "Run '/trans.sh alpine' to install Alpine Linux instead." >&2
    exit 1
}

trap_err() {
    line_no=$1
    ret_no=$2

    error_and_exit "$(
        echo "Line $line_no return $ret_no"
        if [ -f "/trans.sh" ]; then
            sed -n "$line_no"p /trans.sh
        fi
    )"
}

is_run_from_locald() {
    [[ "$0" = "/etc/local.d/*" ]]
}

add_community_repo() {
    # 先检查原来的repo是不是egde
    if grep -q '^http.*/edge/main$' /etc/apk/repositories; then
        alpine_ver=edge
    else
        alpine_ver=v$(cut -d. -f1,2 </etc/alpine-release)
    fi

    if ! grep -q "^http.*/$alpine_ver/community$" /etc/apk/repositories; then
        alpine_mirror=$(grep '^http.*/main$' /etc/apk/repositories | sed 's,/[^/]*/main$,,' | head -1)
        echo $alpine_mirror/$alpine_ver/community >>/etc/apk/repositories
    fi
}

# 有时网络问题下载失败，导致脚本中断
# 因此需要重试
apk() {
    retry 5 command apk "$@" >&2
}

# 在没有设置 set +o pipefail 的情况下，限制下载大小：
# retry 5 command wget | head -c 1048576 会触发 retry，下载 5 次
# command wget "$@" --tries=5 | head -c 1048576 不会触发 wget 自带的 retry，只下载 1 次
wget() {
    echo "$@" | grep -o 'http[^ ]*' >&2
    if command wget 2>&1 | grep -q BusyBox; then
        # busybox wget 没有重试功能
        # 好像默认永不超时
        retry 5 command wget "$@" -T 10
    else
        # 原版 wget 自带重试功能
        command wget --tries=5 --progress=bar:force "$@"
    fi
}

is_have_cmd() {
    # command -v 包括脚本里面的方法
    is_have_cmd_on_disk / "$1"
}

is_have_cmd_on_disk() {
    local os_dir=$1
    local cmd=$2

    for bin_dir in /bin /sbin /usr/bin /usr/sbin; do
        if [ -f "$os_dir$bin_dir/$cmd" ]; then
            return
        fi
    done
    return 1
}

is_num() {
    echo "$1" | grep -Exq '[0-9]*\.?[0-9]*'
}

retry() {
    local max_try=$1
    shift

    if is_num "$1"; then
        local interval=$1
        shift
    else
        local interval=5
    fi

    for i in $(seq $max_try); do
        if "$@"; then
            return
        else
            ret=$?
            if [ $i -ge $max_try ]; then
                return $ret
            fi
            sleep $interval
        fi
    done
}

get_url_type() {
    if [[ "$1" = magnet:* ]]; then
        echo bt
    else
        echo http
    fi
}

is_magnet_link() {
    [[ "$1" = magnet:* ]]
}

download() {
    url=$1
    path=$2

    # 有ipv4地址无ipv4网关的情况下，aria2可能会用ipv4下载，而不是ipv6
    # axel 在 lightsail 上会占用大量cpu
    # https://download.opensuse.org/distribution/leap/15.5/appliances/openSUSE-Leap-15.5-Minimal-VM.x86_64-kvm-and-xen.qcow2
    # https://aria2.github.io/manual/en/html/aria2c.html#cmdoption-o

    # 阿里云源限速，而且检测 user-agent 禁止 axel/aria2 下载
    # aria2 默认 --max-tries 5

    # 默认 --max-tries=5，但以下情况服务器出错，aria2不会重试，而是直接返回错误
    # 因此添加 for 循环
    #     [ERROR] CUID#7 - Download aborted. URI=https://aka.ms/manawindowsdrivers
    # Exception: [AbstractCommand.cc:351] errorCode=1 URI=https://aka.ms/manawindowsdrivers
    #   -> [SocketCore.cc:1019] errorCode=1 SSL/TLS handshake failure:  `not signed by known authorities or invalid'

    # 用 if 的话，报错不会中断脚本
    # if aria2c xxx; then
    #     return
    # fi

    # --user-agent=Wget/1.21.1 \
    # --retry-wait 5

    # 检测大小时已经下载了种子
    if [ "$(get_url_type "$url")" = bt ]; then
        torrent="$(get_torrent_path_by_magnet $url)"
        if ! [ -f "$torrent" ]; then
            download_torrent_by_magnet "$url" "$torrent"
        fi
        url=$torrent
    fi

    # intel 禁止了 aria2 下载
    # 腾讯云 virtio 驱动也禁止了 aria2 下载

    # -o 设置 http 下载文件名
    # -O 设置 bt 首个文件的文件名
    aria2c "$url" \
        -d "$(dirname "$path")" \
        -o "$(basename "$path")" \
        -O "1=$(basename "$path")" \
        -U Wget/1.25.0

    # opensuse 官方镜像支持 metalink
    # aira2 无法重命名用 metalink 下载的文件
    # 需用以下方法重命名
    if head -c 1024 "$path" | grep -Fq 'urn:ietf:params:xml:ns:metalink'; then
        real_file=$(tr -d '\n' <"$path" | sed -E 's|.*<file[[:space:]]+name="([^"]*)".*|\1|')
        mv "$(dirname "$path")/$real_file" "$path"
    fi
}

update_part() {
    sleep 1
    sync

    # partprobe
    # 有分区挂载中会报 Resource busy 错误
    if is_have_cmd partprobe; then
        partprobe /dev/$xda 2>/dev/null || true
    fi

    # partx
    # https://access.redhat.com/solutions/199573
    if is_have_cmd partx; then
        partx -u /dev/$xda
    fi

    # mdev
    # mdev 不会删除 /dev/disk/ 的旧分区，因此手动删除
    # 如果 rm -rf 的时候刚好 mdev 在创建链接，rm -rf 会报错 Directory not empty
    # 因此要先停止 mdev 服务
    # 还要删除 /dev/$xda*?
    ensure_service_stopped mdev
    # 即使停止了 mdev，有时也会报 Directory not empty，因此添加 retry
    retry 5 rm -rf /dev/disk/*

    # 没挂载 modloop 时会提示
    # modprobe: can't change directory to '/lib/modules': No such file or directory
    # 因此强制不显示上面的提示
    mdev -sf 2>/dev/null
    ensure_service_started mdev 2>/dev/null
    sleep 1
}

is_efi() {
    if [ -n "$force" ]; then
        [ "$force" = efi ]
    else
        [ -d /sys/firmware/efi/ ]
    fi
}

is_use_cloud_image() {
    [ -n "$cloud_image" ] && [ "$cloud_image" = 1 ]
}

is_allow_ping() {
    [ -n "$allow_ping" ] && [ "$allow_ping" = 1 ]
}

setup_nginx() {
    apk add nginx
    # shellcheck disable=SC2154
    wget $confhome/logviewer.html -O /logviewer.html
    wget $confhome/logviewer-nginx.conf -O /etc/nginx/http.d/default.conf

    if [ -z "$web_port" ]; then
        web_port=80
    fi
    sed -i "s/@WEB_PORT@/$web_port/gi" /etc/nginx/http.d/default.conf

    # rc-service -q nginx start
    if pgrep nginx >/dev/null; then
        nginx -s reload
    else
        nginx
    fi
}

setup_websocketd() {
    apk add websocketd
    wget $confhome/logviewer.html -O /tmp/index.html
    apk add coreutils

    if [ -z "$web_port" ]; then
        web_port=80
    fi

    pkill websocketd || true
    # websocketd 遇到 \n 才推送，因此要转换 \r 为 \n
    websocketd --port "$web_port" --loglevel=fatal --staticdir=/tmp \
        stdbuf -oL -eL sh -c "tail -fn+0 /reinstall.log | tr '\r' '\n'" &
}

get_approximate_ram_size() {
    # lsmem 需要 util-linux
    if false && is_have_cmd lsmem; then
        ram_size=$(lsmem -b 2>/dev/null | grep 'Total online memory:' | awk '{ print $NF/1024/1024 }')
    fi

    if [ -z $ram_size ]; then
        ram_size=$(free -m | awk '{print $2}' | sed -n '2p')
    fi

    echo "$ram_size"
}

setup_web_if_enough_ram() {
    total_ram=$(get_approximate_ram_size)
    # 512内存才安装
    if [ $total_ram -gt 400 ]; then
        # lighttpd 虽然运行占用内存少，但安装占用空间大
        # setup_lighttpd
        # setup_nginx
        setup_websocketd
    fi
}

setup_lighttpd() {
    apk add lighttpd
    ln -sf /reinstall.html /var/www/localhost/htdocs/index.html
    rc-service -q lighttpd start
}

get_ttys() {
    prefix=$1
    # shellcheck disable=SC2154
    wget $confhome/ttys.sh -O- | sh -s $prefix
}

find_xda() {
    # 出错后再运行脚本，硬盘可能已经格式化，之前记录的分区表 id 无效
    # 因此找到 xda 后要保存 xda 到 /configs/xda

    # 先读取之前保存的
    if xda=$(get_config xda 2>/dev/null) && [ -n "$xda" ]; then
        return
    fi

    # 防止 $main_disk 为空
    if [ -z "$main_disk" ]; then
        error_and_exit "cmdline main_disk is empty."
    fi

    # busybox fdisk/lsblk/blkid 不显示 mbr 分区表 id
    # 可用以下工具：
    # fdisk 在 util-linux-misc 里面，占用大
    # sfdisk 占用小
    # lsblk
    # blkid

    tool=sfdisk

    is_have_cmd $tool && need_install_tool=false || need_install_tool=true
    if $need_install_tool; then
        apk add $tool
    fi

    if [ "$tool" = sfdisk ]; then
        # sfdisk
        for disk in $(get_all_disks); do
            if sfdisk --disk-id "/dev/$disk" | sed 's/0x//' | grep -ix "$main_disk"; then
                xda=$disk
                break
            fi
        done
    else
        # lsblk
        xda=$(lsblk --nodeps -rno NAME,PTUUID | grep -iw "$main_disk" | awk '{print $1}')
    fi

    if [ -n "$xda" ]; then
        set_config xda "$xda"
    else
        error_and_exit "Could not find xda: $main_disk"
    fi

    if $need_install_tool; then
        apk del $tool
    fi
}

get_all_disks() {
    # shellcheck disable=SC2010
    ls /sys/block/ | grep -Ev '^(loop|sr|nbd)'
}

extract_env_from_cmdline() {
    # 提取 finalos/extra 到变量
    for prefix in finalos extra; do
        while read -r line; do
            if [ -n "$line" ]; then
                key=$(echo $line | cut -d= -f1)
                value=$(echo $line | cut -d= -f2-)
                eval "$key='$value'"
            fi
        done < <(xargs -n1 </proc/cmdline | grep "^${prefix}_" | sed "s/^${prefix}_//")
    done
}

ensure_service_started() {
    service=$1

    if ! rc-service -q $service status; then
        if ! retry 5 rc-service -q $service start; then
            error_and_exit "Failed to start $service."
        fi
    fi
}

ensure_service_stopped() {
    service=$1

    if rc-service -q $service status; then
        if ! retry 5 rc-service -q $service stop; then
            error_and_exit "Failed to stop $service."
        fi
    fi
}

mod_motd() {
    # 安装后 alpine 后要恢复默认
    # 自动安装失败后，可能手动安装 alpine，因此无需判断 $distro
    file=/etc/motd
    if ! [ -e $file.orig ]; then
        cp $file $file.orig
        # shellcheck disable=SC2016
        echo "mv "\$mnt$file.orig" "\$mnt$file"" |
            insert_into_file "$(which setup-disk)" before 'cleanup_chroot_mounts "\$mnt"'

        cat <<EOF >$file
Reinstalling...
To view logs run:
tail -fn+1 /reinstall.log
EOF
    fi
}

umount_all() {
    dirs="/mnt /os /iso /wim /installer /nbd /nbd-boot /nbd-efi /root /nix"
    regex=$(echo "$dirs" | sed 's, ,|,g')
    if mounts=$(mount | grep -Ew "on $regex" | awk '{print $3}' | tac); then
        for mount in $mounts; do
            echo "umount $mount"
            umount $mount
        done
    fi
}

# 可能脚本不是首次运行，先清理之前的残留
clear_previous() {
    if is_have_cmd vgchange; then
        umount -R /os /nbd || true
        vgchange -an
        apk add device-mapper
        dmsetup remove_all
    fi
    disconnect_qcow
    # 安装 arch 有 gpg-agent 进程驻留
    pkill gpg-agent || true
    rc-service -q --ifexists --ifstarted nix-daemon stop
    swapoff -a
    umount_all

    # 以下情况 umount -R /1 会提示 busy
    # mount /file1 /1
    # mount /1/file2 /2
}

# virt-what 自动安装 dmidecode，因此同时缓存
cache_dmi_and_virt() {
    if ! [ "$_dmi_and_virt_cached" = 1 ]; then
        apk add virt-what

        # 区分 kvm 和 virtio，原因:
        # 1. 阿里云 c8y virt-what 不显示 kvm
        # 2. 不是所有 kvm 都需要 virtio 驱动，例如 aws nitro
        # 3. virt-what 不会检测 virtio
        _virt=$(
            virt-what

            # hyper-v 环境下 modprobe virtio_scsi 也会创建 /sys/bus/virtio/drivers/virtio_scsi
            # 因此用 devices 判断更准确，有设备时才有 /sys/bus/virtio/drivers/*
            # 或者加上 lspci 检测?

            # 不要用 ls /sys/bus/virtio/devices/* && echo virtio
            # 因为有可能返回值不为 0 而中断脚本
            if ls /sys/bus/virtio/devices/* >/dev/null 2>&1; then
                echo virtio
            fi
        )

        _dmi=$(dmidecode | grep -E '(Manufacturer|Asset Tag|Vendor): ' | awk -F': ' '{print $2}')
        _dmi_and_virt_cached=1
        apk del virt-what
    fi
}

is_virt() {
    cache_dmi_and_virt
    [ -n "$_virt" ]
}

is_virt_contains() {
    cache_dmi_and_virt
    echo "$_virt" | grep -Eiwq "$1"
}

is_dmi_contains() {
    # Manufacturer: Alibaba Cloud
    # Manufacturer: Tencent Cloud
    # Manufacturer: Huawei Cloud
    # Asset Tag: OracleCloud.com
    # Vendor: Amazon EC2
    # Manufacturer: Amazon EC2
    # Asset Tag: Amazon EC2
    cache_dmi_and_virt
    echo "$_dmi" | grep -Eiwq "$1"
}

cache_lspci() {
    if [ -z "$_lspci" ]; then
        apk add pciutils
        _lspci=$(lspci)
        apk del pciutils
    fi
}

is_lspci_contains() {
    cache_lspci
    echo "$_lspci" | grep -Eiwq "$1"
}

get_config() {
    cat "/configs/$1"
}

set_config() {
    printf '%s' "$2" >"/configs/$1"
}

# ubuntu 安装版、el/ol 安装版不使用该密码
get_password_linux_sha512() {
    get_config password-linux-sha512
}

get_password_windows_administrator_base64() {
    get_config password-windows-administrator-base64
}

get_password_plaintext() {
    get_config password-plaintext
}

is_password_plaintext() {
    get_password_plaintext >/dev/null 2>&1
}

show_netconf() {
    grep -r . /dev/netconf/
}

get_ra_to() {
    if [ -z "$_ra" ]; then
        apk add ndisc6
        # 有时会重复收取，所以设置收一份后退出
        echo "Gathering network info..."
        # shellcheck disable=SC2154
        _ra="$(rdisc6 -1 "$ethx")"
        apk del ndisc6

        # 显示网络配置
        info "Network info:"
        echo
        echo "$_ra" | cat -n
        echo
        ip addr | cat -n
        echo
        show_netconf | cat -n
        echo
    fi
    eval "$1='$_ra'"
}

get_netconf_to() {
    case "$1" in
    slaac | dhcpv6 | rdnss | other) get_ra_to ra ;;
    esac

    # shellcheck disable=SC2154
    # debian initrd 没有 xargs
    case "$1" in
    slaac) echo "$ra" | grep 'Autonomous address conf' | grep -q Yes && res=1 || res=0 ;;
    dhcpv6) echo "$ra" | grep 'Stateful address conf' | grep -q Yes && res=1 || res=0 ;;
    rdnss) res=$(echo "$ra" | grep 'Recursive DNS server' | cut -d: -f2-) ;;
    other) echo "$ra" | grep 'Stateful other conf' | grep -q Yes && res=1 || res=0 ;;
    *) res=$(cat /dev/netconf/$ethx/$1) ;;
    esac

    eval "$1='$res'"
}

is_any_ipv4_has_internet() {
    grep -q 1 /dev/netconf/*/ipv4_has_internet
}

is_in_china() {
    grep -q 1 /dev/netconf/*/is_in_china
}

# 有 dhcpv4 不等于有网关，例如 vultr 纯 ipv6
# 没有 dhcpv4 不等于是静态ip，可能是没有 ip
is_dhcpv4() {
    if ! is_ipv4_has_internet || should_disable_dhcpv4; then
        return 1
    fi

    get_netconf_to dhcpv4
    # shellcheck disable=SC2154
    [ "$dhcpv4" = 1 ]
}

is_staticv4() {
    if ! is_ipv4_has_internet; then
        return 1
    fi

    if ! is_dhcpv4; then
        get_netconf_to ipv4_addr
        get_netconf_to ipv4_gateway
        if [ -n "$ipv4_addr" ] && [ -n "$ipv4_gateway" ]; then
            return 0
        fi
    fi
    return 1
}

is_staticv6() {
    if ! is_ipv6_has_internet; then
        return 1
    fi

    if ! is_slaac && ! is_dhcpv6; then
        get_netconf_to ipv6_addr
        get_netconf_to ipv6_gateway
        if [ -n "$ipv6_addr" ] && [ -n "$ipv6_gateway" ]; then
            return 0
        fi
    fi
    return 1
}

is_dhcpv6_or_slaac() {
    get_netconf_to dhcpv6_or_slaac
    # shellcheck disable=SC2154
    [ "$dhcpv6_or_slaac" = 1 ]
}

is_ipv4_has_internet() {
    get_netconf_to ipv4_has_internet
    # shellcheck disable=SC2154
    [ "$ipv4_has_internet" = 1 ]
}

is_ipv6_has_internet() {
    get_netconf_to ipv6_has_internet
    # shellcheck disable=SC2154
    [ "$ipv6_has_internet" = 1 ]
}

should_disable_dhcpv4() {
    get_netconf_to should_disable_dhcpv4
    # shellcheck disable=SC2154
    [ "$should_disable_dhcpv4" = 1 ]
}

should_disable_accept_ra() {
    get_netconf_to should_disable_accept_ra
    # shellcheck disable=SC2154
    [ "$should_disable_accept_ra" = 1 ]
}

should_disable_autoconf() {
    get_netconf_to should_disable_autoconf
    # shellcheck disable=SC2154
    [ "$should_disable_autoconf" = 1 ]
}

is_slaac() {
    # 如果是静态（包括自动获取到 IP 但无法联网而切换成静态）直接返回 1，不考虑 ra
    # 防止部分机器slaac/dhcpv6获取的ip/网关无法上网

    # 有可能 ra 的 dhcpv6/slaac 是打开的，但实测无法获取到 ipv6 地址
    # is_dhcpv6_or_slaac 是实测结果，因此如果实测不通过，也返回 1

    # 不要判断 is_staticv6，因为这会导致死循环
    if ! is_ipv6_has_internet || ! is_dhcpv6_or_slaac || should_disable_accept_ra || should_disable_autoconf; then
        return 1
    fi
    get_netconf_to slaac
    # shellcheck disable=SC2154
    [ "$slaac" = 1 ]
}

is_dhcpv6() {
    # 如果是静态（包括自动获取到 IP 但无法联网而切换成静态）直接返回 1，不考虑 ra
    # 防止部分机器slaac/dhcpv6获取的ip/网关无法上网

    # 有可能 ra 的 dhcpv6/slaac 是打开的，但实测无法获取到 ipv6 地址
    # is_dhcpv6_or_slaac 是实测结果，因此如果实测不通过，也返回 1

    # 不要判断 is_staticv6，因为这会导致死循环
    if ! is_ipv6_has_internet || ! is_dhcpv6_or_slaac || should_disable_accept_ra || should_disable_autoconf; then
        return 1
    fi
    get_netconf_to dhcpv6

    # shellcheck disable=SC2154
    # 甲骨文即使没有添加 IPv6 地址，RA DHCPv6 标志也是开的
    # 部分系统开机需要等 DHCPv6 超时
    # 这种情况需要禁用 DHCPv6
    if [ "$dhcpv6" = 1 ] && ! ip -6 -o addr show scope global dev "$ethx" | grep -q .; then
        echo 'DHCPv6 flag is on, but DHCPv6 is not working.'
        return 1
    fi

    [ "$dhcpv6" = 1 ]
}

is_have_ipv6() {
    is_slaac || is_dhcpv6 || is_staticv6
}

is_enable_other_flag() {
    get_netconf_to other
    # shellcheck disable=SC2154
    [ "$other" = 1 ]
}

is_have_rdnss() {
    # rdnss 可能有几个
    get_netconf_to rdnss
    [ -n "$rdnss" ]
}

# dd 完检测到镜像是 windows 时会改写此方法
is_windows() {
    [ "$distro" = windows ]
}

# 15063 或之后才支持 rdnss
is_windows_support_rdnss() {
    [ "$build_ver" -ge 15063 ]
}

get_windows_version_from_dll() {
    local dll=$1
    [ -f "$dll" ] || error_and_exit "File not found: $dll"

    apk add pev
    local ver
    ver="$(peres -v "$dll" | grep 'Product Version:' | awk '{print $NF}')"
    echo "Version: $ver" >&2
    IFS=. read -r nt_ver_major nt_ver_minor build_ver rev_ver _ < <(echo "$ver")
    nt_ver="$nt_ver_major.$nt_ver_minor"
    apk del pev
}

is_elts() {
    [ -n "$elts" ] && [ "$elts" = 1 ]
}

is_need_set_ssh_keys() {
    [ -s /configs/ssh_keys ]
}

is_need_change_ssh_port() {
    [ -n "$ssh_port" ] && ! [ "$ssh_port" = 22 ]
}

is_need_change_rdp_port() {
    [ -n "$rdp_port" ] && ! [ "$rdp_port" = 3389 ]
}

is_need_manual_set_dnsv6() {
    # 有没有可能是静态但是有 rdnss？
    ! is_have_ipv6 && return $FALSE
    is_dhcpv6 && return $FALSE
    is_staticv6 && return $TRUE
    is_slaac && ! is_enable_other_flag &&
        { ! is_have_rdnss || { is_have_rdnss && is_windows && ! is_windows_support_rdnss; }; }
}

get_current_dns() {
    mark=$(
        case "$1" in
        4) echo . ;;
        6) echo : ;;
        esac
    )
    # debian 11 initrd 没有 xargs awk
    # debian 12 initrd 没有 xargs
    if false; then
        grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -F "$mark" | cut -d '%' -f1
    else
        grep '^nameserver' /etc/resolv.conf | cut -d' ' -f2 | grep -F "$mark" | cut -d '%' -f1
    fi
}

to_upper() {
    tr '[:lower:]' '[:upper:]'
}

to_lower() {
    tr '[:upper:]' '[:lower:]'
}

del_cr() {
    sed 's/\r$//'
}

del_comment_lines() {
    sed '/^[[:space:]]*#/d'
}

del_empty_lines() {
    sed '/^[[:space:]]*$/d'
}

del_head_empty_lines_inplace() {
    # 从第一行直到找到 ^[:space:]
    # 这个区间内删除所有空行
    sed -i '1,/[^[:space:]]/ { /^[[:space:]]*$/d }' "$@"
}

get_part_num_by_part() {
    dev_part=$1
    echo "$dev_part" | grep -o '[0-9]*' | tail -1
}

get_fallback_efi_file_name() {
    case $(arch) in
    x86_64) echo bootx64.efi ;;
    aarch64) echo bootaa64.efi ;;
    *) error_and_exit ;;
    esac
}

del_invalid_efi_entry() {
    info "del invalid EFI entry"
    apk add lsblk efibootmgr

    efibootmgr --quiet --remove-dups

    while read -r line; do
        part_uuid=$(echo "$line" | awk -F ',' '{print $3}')
        efi_index=$(echo "$line" | grep_efi_index)
        if ! lsblk -o PARTUUID | grep -q "$part_uuid"; then
            echo "Delete invalid EFI Entry: $line"
            efibootmgr --quiet --bootnum "$efi_index" --delete-bootnum
        fi
    done < <(efibootmgr | grep 'HD(.*,GPT,')
}

# reinstall.sh 有同名方法
grep_efi_index() {
    awk '{print $1}' | sed -e 's/Boot//' -e 's/\*//'
}

# 某些机器可能不会回落到 bootx64.efi
# 阿里云 ECS 启动项有 EFI Shell
# 添加 bootx64.efi 到最后的话，会进入 EFI Shell
# 因此添加到最前面
add_default_efi_to_nvram() {
    info "add default EFI to nvram"

    apk add lsblk efibootmgr

    if efi_row=$(lsblk /dev/$xda -ro NAME,PARTTYPE,PARTUUID | grep -i "$EFI_UUID"); then
        efi_part_uuid=$(echo "$efi_row" | awk '{print $3}')
        efi_part_name=$(echo "$efi_row" | awk '{print $1}')
        efi_part_num=$(get_part_num_by_part "$efi_part_name")
        efi_file=$(get_fallback_efi_file_name)

        # 创建条目，先判断是否已经存在
        # 好像没必要先判断
        if true || ! efibootmgr | grep -i "HD($efi_part_num,GPT,$efi_part_uuid,.*)/File(\\\EFI\\\boot\\\\$efi_file)"; then
            efibootmgr --create \
                --disk "/dev/$xda" \
                --part "$efi_part_num" \
                --label "$efi_file" \
                --loader "\\EFI\\boot\\$efi_file"
        fi
    else
        # shellcheck disable=SC2154
        if [ "$confirmed_no_efi" = 1 ]; then
            echo 'Confirmed no EFI in previous step.'
        else
            # reinstall.sh 里确认过一遍，但是逻辑扇区大于 512 时，可能漏报？
            # 这里的应该会根据逻辑扇区来判断？
            echo "
Warning: This machine is currently using EFI boot, but the main hard drive does not have an EFI partition.
If this machine supports Legacy BIOS boot (CSM), you can safely restart into the new system by running the reboot command.
If this machine does not support Legacy BIOS boot (CSM), you will not be able to enter the new system after rebooting.

警告：本机目前使用 EFI 引导，但主硬盘没有 EFI 分区。
如果本机支持 Legacy BIOS 引导 (CSM)，你可以运行 reboot 命令安全地重启到新系统。
如果本机不支持 Legacy BIOS 引导 (CSM)，重启后将无法进入新系统。
"
            exit
        fi
    fi
}

unix2dos() {
    target=$1

    # 先原地unix2dos，出错再用cat，可最大限度保留文件权限
    if ! command unix2dos $target 2>/tmp/unix2dos.log; then
        # 出错后删除 unix2dos 创建的临时文件
        rm "$(awk -F: '{print $2}' /tmp/unix2dos.log | xargs)"
        tmp=$(mktemp)
        cp $target $tmp
        command unix2dos $tmp
        # cat 可以保留权限
        cat $tmp >$target
        rm $tmp
    fi
}

insert_into_file() {
    file=$1
    location=$2
    regex_to_find=$3
    shift 3

    # 默认 grep -E
    if [ $# -eq 0 ]; then
        set -- -E
    fi

    if [ "$location" = head ]; then
        bak=$(mktemp)
        cp $file $bak
        cat - $bak >$file
    else
        line_num=$(grep "$@" -n "$regex_to_find" "$file" | cut -d: -f1)

        found_count=$(echo "$line_num" | wc -l)
        if [ ! "$found_count" -eq 1 ]; then
            return 1
        fi

        case "$location" in
        before) line_num=$((line_num - 1)) ;;
        after) ;;
        *) return 1 ;;
        esac

        sed -i "${line_num}r /dev/stdin" "$file"
    fi
}

get_eths() {
    (
        cd /dev/netconf
        ls
    )
}

is_distro_like_debian() {
    [ "$distro" = debian ] || [ "$distro" = kali ]
}

create_ifupdown_config() {
    conf_file=$1

    rm -f $conf_file

    if is_distro_like_debian; then
        cat <<EOF >>$conf_file
source /etc/network/interfaces.d/*

EOF
    fi

    # 生成 lo配置
    cat <<EOF >>$conf_file
auto lo
iface lo inet loopback
EOF

    # ethx
    for ethx in $(get_eths); do
        mode=auto
        # shellcheck disable=SC2154
        if false; then
            if { [ "$distro" = debian ] && [ "$releasever" -ge 12 ]; } ||
                [ "$distro" = kali ]; then
                # alice + allow-hotplug 会有问题
                # 问题 1 debian 9/10/11/12:
                # 如果首次启动时，/etc/networking/interfaces 的 ethx 跟安装时不同
                # 即使启动 networking 服务前成功执行了 fix-eth-name.sh ，网卡也不会启动
                # 测试方法: 安装时手动修改 /etc/networking/interfaces enp3s0 为其他名字
                # 问题 2 debian 9/10/11:
                # 重启系统后会自动启动网卡，但运行 systemctl restart networking 会关闭网卡
                # 可能的原因: /lib/systemd/system/networking.service 没有 hotplug 相关内容，而 debian 12+ 有
                if [ -f /etc/network/devhotplug ] && grep -wo "$ethx" /etc/network/devhotplug; then
                    mode=allow-hotplug
                fi
            fi

            # if is_have_cmd udevadm; then
            #     enpx=$(udevadm test-builtin net_id /sys/class/net/$ethx 2>&1 | grep ID_NET_NAME_PATH= | cut -d= -f2)
            # fi
        fi

        # dmit debian 普通内核和云内核网卡名不一致，因此需要 rename
        # 安装系统时 ens18
        # 普通内核   ens18
        # 云内核     enp6s18
        # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=928923

        # 头部
        get_netconf_to mac_addr
        {
            echo
            # 这是标记，fix-eth-name 要用，不要删除
            # shellcheck disable=SC2154
            echo "# mac $mac_addr"
            echo $mode $ethx
        } >>$conf_file

        # ipv4
        if is_dhcpv4; then
            echo "iface $ethx inet dhcp" >>$conf_file

        elif is_staticv4; then
            get_netconf_to ipv4_addr
            get_netconf_to ipv4_gateway
            cat <<EOF >>$conf_file
iface $ethx inet static
    address $ipv4_addr
    gateway $ipv4_gateway
EOF
            # dns
            if list=$(get_current_dns 4); then
                for dns in $list; do
                    cat <<EOF >>$conf_file
    dns-nameservers $dns
EOF
                done
            fi
        fi

        # ipv6
        if is_slaac; then
            echo "iface $ethx inet6 auto" >>$conf_file

        elif is_dhcpv6; then
            echo "iface $ethx inet6 dhcp" >>$conf_file

        elif is_staticv6; then
            get_netconf_to ipv6_addr
            get_netconf_to ipv6_gateway
            cat <<EOF >>$conf_file
iface $ethx inet6 static
    address $ipv6_addr
    gateway $ipv6_gateway
EOF
            # debian 9
            # ipv4 支持静态 onlink 网关
            # ipv6 不支持静态 onlink 网关，需使用 post-up 添加，未测试动态
            # ipv6 也不支持直接 ip route add default via xxx onlink
            if [ "$distro" = debian ] && [ "$releasever" -le 9 ]; then
                # debian 添加 gateway 失败时不会执行 post-up
                # 因此 gateway post-up 只能二选一

                # 注释最后一行，也就是 gateway
                sed -Ei '$s/^( *)/\1# /' "$conf_file"
                cat <<EOF >>$conf_file
    post-up ip route add $ipv6_gateway dev $ethx
    post-up ip route add default via $ipv6_gateway dev $ethx
EOF
            fi
        fi

        # dns
        # 有 ipv6 但需设置 dns 的情况
        if is_need_manual_set_dnsv6; then
            for dns in $(get_current_dns 6); do
                cat <<EOF >>$conf_file
    dns-nameserver $dns
EOF
            done
        fi

        # 禁用 ra
        if should_disable_accept_ra; then
            if [ "$distro" = alpine ]; then
                cat <<EOF >>$conf_file
    pre-up echo 0 >/proc/sys/net/ipv6/conf/$ethx/accept_ra
EOF
            else
                cat <<EOF >>$conf_file
    accept_ra 0
EOF
            fi
        fi

        # 禁用 autoconf
        if should_disable_autoconf; then
            if [ "$distro" = alpine ]; then
                cat <<EOF >>$conf_file
    pre-up echo 0 >/proc/sys/net/ipv6/conf/$ethx/autoconf
EOF
            else
                cat <<EOF >>$conf_file
    autoconf 0
EOF
            fi
        fi
    done
}

newline_to_comma() {
    tr '\n' ','
}

space_to_newline() {
    sed 's/ /\n/g'
}

trim() {
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

quote_word() {
    sed -E 's/([^[:space:]]+)/"\1"/g'
}

quote_line() {
    awk '{print "\""$0"\""}'
}

add_space() {
    space_count=$1

    spaces=$(printf '%*s' "$space_count" '')
    sed "s/^/$spaces/"
}

# 不够严谨，谨慎使用
nix_replace() {
    local key=$1
    local value=$2
    local type=$3
    local file=$4
    local key_ value_

    key_=$(echo "$key" | sed 's \. \\\. g') # . 改成 \.

    if [ "$type" = array ]; then
        local value_="[ $value ]"
    fi

    sed -i "s/$key_ =.*/$key = $value_;/" "$file"
}

get_cpu_vendor() {
    cpu_vendor=$(grep 'vendor_id' /proc/cpuinfo | head -1 | awk '{print $NF}')
    case "$cpu_vendor" in
    GenuineIntel) echo intel ;;
    AuthenticAMD) echo amd ;;
    *) echo other ;;
    esac
}

min() {
    printf "%d\n" "$@" | sort -n | head -n 1
}

# 设置线程
# 根据 cpu 核数，每个线程的内存，取最小值
get_build_threads() {
    threads_per_mb=$1

    threads_by_core=$(nproc)
    threads_by_ram=$(($(get_approximate_ram_size) / threads_per_mb))
    [ $threads_by_ram -eq 0 ] && threads_by_ram=1
    min $threads_by_ram $threads_by_core
}

add_newline() {
    # shellcheck disable=SC1003
    case "$1" in
    head | start) sed -e '1s/^/\n/' ;;
    tail | end) sed -e '$a\\' ;;
    both) sed -e '1s/^/\n/' -e '$a\\' ;;
    esac
}

add_systemd_service() {
    local os_dir=$1
    local service_name=$2

    download "$confhome/$service_name.service" "$os_dir/etc/systemd/system/$service_name.service"
    chroot "$os_dir" systemctl enable "$service_name.service"

    # aosc 首次开机会执行 preset-all
    # 因此需要设置 fix-eth-name 的 preset 状态
    # 不然首次开机 /etc/systemd/system/multi-user.target.wants/fix-eth-name.service 会被删除
    # 通常 /etc/systemd/system-preset/ 文件夹要新建，因此不放在这里

    # 可能是 /usr/lib/systemd/system-preset/ 或者 /lib/systemd/system-preset/
    if [ -d "$os_dir/usr/lib/systemd/system-preset" ]; then
        echo "enable $service_name.service" >"$os_dir/usr/lib/systemd/system-preset/01-$service_name.preset"
    else
        echo "enable $service_name.service" >"$os_dir/lib/systemd/system-preset/01-$service_name.preset"
    fi
}

add_fix_eth_name_systemd_service() {
    local os_dir=$1

    # 无需执行 systemctl daemon-reload
    # 因为 chroot 下执行会提示 Running in chroot, ignoring command 'daemon-reload'
    download "$confhome/fix-eth-name.sh" "$os_dir/fix-eth-name.sh"
    add_systemd_service "$os_dir" fix-eth-name
}

get_frpc_url() {
    wget "$confhome/get-frpc-url.sh" -O- | sh -s "$@"
}

add_frpc_systemd_service_if_need() {
    local os_dir=$1

    if [ -s /configs/frpc.toml ]; then
        mkdir -p "$os_dir/usr/local/bin"
        mkdir -p "$os_dir/usr/local/etc/frpc"

        # 下载 frpc
        # 注意下载的 frpc owner 不是 root:root
        frpc_url=$(get_frpc_url linux)
        basename=$(echo "$frpc_url" | awk -F/ '{print $NF}' | sed 's/\.tar\.gz//')
        download "$frpc_url" "$os_dir/frpc.tar.gz"
        tar xzf "$os_dir/frpc.tar.gz" "$basename/frpc" -O >"$os_dir/usr/local/bin/frpc"
        rm -f "$os_dir/frpc.tar.gz"
        chmod a+x "$os_dir/usr/local/bin/frpc"

        # frpc conf
        cp /configs/frpc.toml "$os_dir/usr/local/etc/frpc/frpc.toml"

        # 添加服务
        add_systemd_service "$os_dir" frpc
    fi
}

basic_init() {
    os_dir=$1

    # 此时不能用
    # chroot $os_dir timedatectl set-timezone Asia/Shanghai
    # Failed to create bus connection: No such file or directory

    # debian 11 没有 systemd-firstboot
    if is_have_cmd_on_disk $os_dir systemd-firstboot; then
        if chroot $os_dir systemd-firstboot --help | grep -wq '\--force'; then
            chroot $os_dir systemd-firstboot --timezone=Asia/Shanghai --force
        else
            chroot $os_dir systemd-firstboot --timezone=Asia/Shanghai
        fi
    fi

    # gentoo 不会自动创建 machine-id
    # clear_machine_id $os_dir

    # sshd
    chroot $os_dir ssh-keygen -A

    sshd_enabled=false
    sshs="sshd.service ssh.service sshd.socket ssh.socket"
    for i in $sshs; do
        if chroot $os_dir systemctl -q is-enabled $i; then
            sshd_enabled=true
            break
        fi
    done
    if ! $sshd_enabled; then
        for i in $sshs; do
            if chroot $os_dir systemctl -q enable $i; then
                break
            fi
        done
    fi

    if is_need_change_ssh_port; then
        change_ssh_port $os_dir $ssh_port
    fi

    # 公钥/密码
    if is_need_set_ssh_keys; then
        set_ssh_keys_and_del_password $os_dir
    else
        change_root_password $os_dir
        allow_root_password_login $os_dir
        allow_password_login $os_dir
    fi

    # 下载 fix-eth-name.service
    # 即使开了 net.ifnames=0 也需要
    # 因为 alpine live 和目标系统的网卡顺序可能不同
    add_fix_eth_name_systemd_service $os_dir

    # frpc
    add_frpc_systemd_service_if_need $os_dir
}

get_http_file_size() {
    url=$1

    # 网址重定向可能得到多个 Content-Length, 选最后一个
    wget --spider -S "$url" 2>&1 | grep 'Content-Length:' |
        tail -1 | awk '{print $2}' | grep .
}

get_url_hash() {
    url=$1

    echo "$url" | md5sum | awk '{print $1}'
}

aria2c() {
    if ! is_have_cmd aria2c; then
        apk add aria2
    fi

    # stdbuf 在 coreutils 包里面
    if ! is_have_cmd stdbuf; then
        apk add coreutils
    fi

    # 指定 bt 种子时没有链接，因此忽略错误
    echo "$@" | grep -oE '(http|https|magnet):[^ ]*' || true

    # 下载 tracker
    # 在 sub shell 里面无法保存变量，因此写入到文件
    if echo "$@" | grep -Eq 'magnet:|\.torrent' && ! [ -f "/tmp/trackers" ]; then
        # 独自一行下载，不然下载失败不会报错
        # 里面有空行
        # txt=$(wget -O- https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt | grep .)
        # txt=$(wget -O- https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt | grep .)
        txt=$(wget -O- https://cf.trackerslist.com/best.txt | grep .)
        # sed 删除最后一个逗号
        echo "$txt" | newline_to_comma | sed 's/,$//' >/tmp/trackers
    fi

    # --dht-entry-point=router.bittorrent.com:6881 \
    # --dht-entry-point=dht.transmissionbt.com:6881 \
    # --dht-entry-point=router.utorrent.com:6881 \
    retry 5 5 stdbuf -oL -eL aria2c \
        -x4 \
        --seed-time=0 \
        --allow-overwrite=true \
        --summary-interval=0 \
        --max-tries 1 \
        --bt-tracker="$([ -f "/tmp/trackers" ] && cat /tmp/trackers)" \
        "$@"
}

download_torrent_by_magnet() {
    url=$1
    dst=$2

    url_hash=$(get_url_hash "$url")

    mkdir -p /tmp/bt/$url_hash

    # 不支持 -o bt.torrent 指定文件名
    aria2c "$url" \
        --bt-metadata-only=true \
        --bt-save-metadata=true \
        -d /tmp/bt/$url_hash

    mv /tmp/bt/$url_hash/*.torrent "$dst"
    rm -rf /tmp/bt/$url_hash
}

get_torrent_path_by_magnet() {
    echo "/tmp/bt/$(get_url_hash "$1").torrent"
}

get_bt_file_size() {
    url=$1

    torrent="$(get_torrent_path_by_magnet $url)"
    download_torrent_by_magnet "$url" "$torrent" >&2

    # 列出第一个文件的大小
    # idx|path/length
    # ===+===========================================================================
    #   1|./zh-cn_windows_11_consumer_editions_version_24h2_updated_jan_2025_x64_dvd_7a8e5a29.iso
    #    |6.1GiB (6,557,558,784)

    aria2c --show-files=true "$torrent" |
        grep -F -A1 '  1|./' | tail -1 | grep -o '(.*)' | sed -E 's/[(),]//g' | grep .
}

get_link_file_size() {
    if is_magnet_link "$1" >&2; then
        get_bt_file_size "$1"
    else
        get_http_file_size "$1"
    fi
}

pipe_extract() {
    # alpine busybox 自带 gzip，但官方版也许性能更好
    case "$img_type_warp" in
    xz | gzip | zstd)
        apk add $img_type_warp
        "$img_type_warp" -dc
        ;;
    tar)
        apk add tar
        tar x -O
        ;;
    tar.*)
        type=$(echo "$img_type_warp" | cut -d. -f2)
        apk add tar "$type"
        tar x "--$type" -O
        ;;
    '') cat ;;
    *) error_and_exit "Not supported img_type_warp: $img_type_warp" ;;
    esac
}

dd_raw_with_extract() {
    info "dd raw"

    # 用官方 wget，一来带进度条，二来自带重试功能
    apk add wget

    if ! wget $img -O- | pipe_extract >/dev/$xda 2>/tmp/dd_stderr; then
        # vhd 文件结尾有 512 字节额外信息，可以忽略
        if grep -iq 'No space' /tmp/dd_stderr; then
            apk add parted
            disk_size=$(get_disk_size /dev/$xda)
            disk_end=$((disk_size - 1))

            # 如果报错，那大概是因为镜像比硬盘大
            if last_part_end=$(parted -sf /dev/$xda 'unit b print' ---pretend-input-tty |
                del_empty_lines | tail -1 | awk '{print $3}' | sed 's/B//' | grep .); then

                echo "Last part end: $last_part_end"
                echo "Disk end:      $disk_end"

                if [ "$last_part_end" -le "$disk_end" ]; then
                    echo "Safely ignore no space error."
                    return
                fi
            fi
        fi
        error_and_exit "$(cat /tmp/dd_stderr)"
    fi
}

get_disk_sector_count() {
    # cat /proc/partitions
    blockdev --getsz "$1"
}

get_disk_size() {
    blockdev --getsize64 "$1"
}

get_disk_logic_sector_size() {
    blockdev --getss "$1"
}

is_4kn() {
    [ "$(blockdev --getss "$1")" = 4096 ]
}

is_xda_gt_2t() {
    disk_size=$(get_disk_size /dev/$xda)
    disk_2t=$((2 * 1024 * 1024 * 1024 * 1024))
    [ "$disk_size" -gt "$disk_2t" ]
}

create_part() {
    # 除了 dd 都会用到
    info "Create Part"

    # 分区工具
    apk add parted e2fsprogs
    if is_efi; then
        apk add dosfstools
    fi

    # 清除分区签名
    # TODO: 先检测iso链接/各种链接
    # wipefs -a /dev/$xda

    # xda*1 星号用于 nvme0n1p1 的字母 p
    # shellcheck disable=SC2154
    if is_use_cloud_image; then
        installer_part_size="$(get_cloud_image_part_size)"
        # 这几个系统不使用dd，而是复制文件
        if [ "$distro" = centos ] || [ "$distro" = almalinux ] || [ "$distro" = rocky ] ||
            [ "$distro" = oracle ] || [ "$distro" = redhat ] ||
            [ "$distro" = ubuntu ]; then
            # 这里的 fs 没有用，最终使用目标系统的格式化工具
            fs=ext4
            if is_efi; then
                parted /dev/$xda -s -- \
                    mklabel gpt \
                    mkpart '" "' fat32 1MiB 101MiB \
                    mkpart '" "' $fs 101MiB -$installer_part_size \
                    mkpart '" "' ext4 -$installer_part_size 100% \
                    set 1 esp on
                update_part

                mkfs.fat -n efi /dev/$xda*1           #1 efi
                echo                                  #2 os 用目标系统的格式化工具
                mkfs.ext4 -F -L installer /dev/$xda*3 #3 installer
            else
                parted /dev/$xda -s -- \
                    mklabel gpt \
                    mkpart '" "' ext4 1MiB 2MiB \
                    mkpart '" "' $fs 2MiB -$installer_part_size \
                    mkpart '" "' ext4 -$installer_part_size 100% \
                    set 1 bios_grub on
                update_part

                echo                                  #1 bios_boot
                echo                                  #2 os 用目标系统的格式化工具
                mkfs.ext4 -F -L installer /dev/$xda*3 #3 installer
            fi
        else
            # 使用 dd qcow2
            # fedora debian opensuse arch gentoo
            parted /dev/$xda -s -- \
                mklabel gpt \
                mkpart '" "' ext4 1MiB -$installer_part_size \
                mkpart '" "' ext4 -$installer_part_size 100%
            update_part

            mkfs.ext4 -F -L os /dev/$xda*1        #1 os
            mkfs.ext4 -F -L installer /dev/$xda*2 #2 installer
        fi
    else
        # 安装红帽系或ubuntu
        # 对于红帽系是临时分区表，安装时除了 installer 分区，其他分区会重建为默认的大小
        # 对于ubuntu是最终分区表，因为 ubuntu 的安装器不能调整个别分区，只能重建整个分区表
        # installer 2g分区用fat格式刚好塞得下ubuntu-22.04.3 iso，而ext4塞不下或者需要改参数
        if [ "$distro" = ubuntu ]; then
            if ! size_bytes=$(get_http_file_size "$iso"); then
                # 默认值，假设 iso 3g
                size_bytes=$((3 * 1024 * 1024 * 1024))
            fi
            installer_part_size="$(get_part_size_mb_for_file_size_b $size_bytes)MiB"
        else
            # redhat
            installer_part_size=2GiB
        fi

        # centos 7 无法加载alpine格式化的ext4
        # 要关闭这个属性
        ext4_opts="-O ^metadata_csum"
        apk add dosfstools

        if is_efi; then
            # efi
            parted /dev/$xda -s -- \
                mklabel gpt \
                mkpart '" "' fat32 1MiB 1025MiB \
                mkpart '" "' ext4 1025MiB -$installer_part_size \
                mkpart '" "' ext4 -$installer_part_size 100% \
                set 1 boot on
            update_part

            mkfs.fat -n efi /dev/$xda*1                      #1 efi
            mkfs.ext4 -F -L os /dev/$xda*2                   #2 os
            mkfs.ext4 -F -L installer $ext4_opts /dev/$xda*3 #2 installer
        elif is_xda_gt_2t; then
            # bios > 2t
            parted /dev/$xda -s -- \
                mklabel gpt \
                mkpart '" "' ext4 1MiB 2MiB \
                mkpart '" "' ext4 2MiB -$installer_part_size \
                mkpart '" "' ext4 -$installer_part_size 100% \
                set 1 bios_grub on
            update_part

            echo                                             #1 bios_boot
            mkfs.ext4 -F -L os /dev/$xda*2                   #2 os
            mkfs.ext4 -F -L installer $ext4_opts /dev/$xda*3 #3 installer
        else
            # bios
            parted /dev/$xda -s -- \
                mklabel msdos \
                mkpart primary ext4 1MiB -$installer_part_size \
                mkpart primary ext4 -$installer_part_size 100% \
                set 1 boot on
            update_part

            mkfs.ext4 -F -L os /dev/$xda*1                   #1 os
            mkfs.ext4 -F -L installer $ext4_opts /dev/$xda*2 #2 installer
        fi
        update_part
    fi

    update_part

    # alpine 删除分区工具，防止 256M 小机爆内存
    # setup-disk /dev/sda 会保留格式化工具，我们也保留
    if [ "$distro" = alpine ]; then
        apk del parted
    fi
}

umount_pseudo_fs() {
    os_dir=$(realpath "$1")

    dirs="/proc /sys /dev /run"
    regex=$(echo "$dirs" | sed 's, ,|,g')
    if mounts=$(mount | grep -Ew "on $os_dir($regex)" | awk '{print $3}' | tac); then
        for mount in $mounts; do
            echo "umount $mount"
            umount $mount
        done
    fi
}

mount_pseudo_fs() {
    os_dir=$1

    mkdir -p $os_dir/proc/ $os_dir/sys/ $os_dir/dev/ $os_dir/run/

    # https://wiki.archlinux.org/title/Chroot#Using_chroot
    mount -t proc /proc $os_dir/proc/
    mount -t sysfs /sys $os_dir/sys/
    mount --rbind /dev $os_dir/dev/
    mount --rbind /run $os_dir/run/
    if is_efi; then
        mount --rbind /sys/firmware/efi/efivars $os_dir/sys/firmware/efi/efivars/
    fi
}

get_yq_name() {
    if grep -q '3\.1[6789]' /etc/alpine-release; then
        echo yq
    else
        echo yq-go
    fi
}

create_cloud_init_network_config() {
    ci_file=$1
    recognize_static6=${2:-true}
    recognize_ipv6_types=${3:-true}

    info "Create Cloud-init network config"

    # 防止文件未创建
    mkdir -p "$(dirname "$ci_file")"
    touch "$ci_file"

    apk add "$(get_yq_name)"

    need_set_dns4=false
    need_set_dns6=false

    config_id=0
    for ethx in $(get_eths); do
        get_netconf_to mac_addr

        # shellcheck disable=SC2154
        yq -i ".network.version=1 |
           .network.config[$config_id].type=\"physical\" |
           .network.config[$config_id].name=\"$ethx\" |
           .network.config[$config_id].mac_address=(\"$mac_addr\" | . style=\"single\")
           " $ci_file

        subnet_id=0

        # ipv4
        if is_dhcpv4; then
            yq -i ".network.config[$config_id].subnets[$subnet_id] = {\"type\": \"dhcp4\"}" $ci_file
            subnet_id=$((subnet_id + 1))
        elif is_staticv4; then
            need_set_dns4=true
            get_netconf_to ipv4_addr
            get_netconf_to ipv4_gateway
            yq -i ".network.config[$config_id].subnets[$subnet_id] = {
                    \"type\": \"static\",
                    \"address\": \"$ipv4_addr\",
                    \"gateway\": \"$ipv4_gateway\" }
                    " $ci_file

            # 旧版 cloud-init 有 bug
            # 有的版本会只从第一种配置中读取 dns，有的从第二种读取
            # 因此写两种配置
            # https://github.com/canonical/cloud-init/commit/1b8030e0c7fd6fbff7e38ad1e3e6266ae50c83a5
            for cur in $(get_current_dns 4); do
                yq -i ".network.config[$config_id].subnets[$subnet_id].dns_nameservers += [\"$cur\"]" $ci_file
            done
            subnet_id=$((subnet_id + 1))
        fi

        # ipv6
        # slaac:  ipv6_slaac
        # └─enable_other_flag: ipv6_dhcpv6-stateless
        # dhcpv6: ipv6_dhcpv6-stateful

        # ipv6
        if is_slaac; then
            if $recognize_ipv6_types; then
                if is_enable_other_flag; then
                    type=ipv6_dhcpv6-stateless
                else
                    type=ipv6_slaac
                fi
            else
                type=dhcp6
            fi
            yq -i ".network.config[$config_id].subnets[$subnet_id] = {\"type\": \"$type\"}" $ci_file

        elif is_dhcpv6; then
            if $recognize_ipv6_types; then
                type=ipv6_dhcpv6-stateful
            else
                type=dhcp6
            fi
            yq -i ".network.config[$config_id].subnets[$subnet_id] = {\"type\": \"$type\"}" $ci_file

        elif is_staticv6; then
            get_netconf_to ipv6_addr
            get_netconf_to ipv6_gateway
            if $recognize_static6; then
                type_ipv6_static=static6
            else
                type_ipv6_static=static
            fi
            yq -i ".network.config[$config_id].subnets[$subnet_id] = {
                    \"type\": \"$type_ipv6_static\",
                    \"address\": \"$ipv6_addr\",
                    \"gateway\": \"$ipv6_gateway\" }
                    " $ci_file
        fi
        # 无法设置 autoconf = false ?
        if should_disable_accept_ra; then
            yq -i ".network.config[$config_id].accept-ra = false" $ci_file
        fi

        # 有 ipv6 但需设置 dns 的情况
        if is_need_manual_set_dnsv6; then
            need_set_dns6=true
            for cur in $(get_current_dns 6); do
                yq -i ".network.config[$config_id].subnets[$subnet_id].dns_nameservers += [\"$cur\"]" $ci_file
            done
        fi

        config_id=$((config_id + 1))
    done

    if $need_set_dns4 || $need_set_dns6; then
        yq -i ".network.config[$config_id].type=\"nameserver\"" $ci_file
        if $need_set_dns4; then
            for cur in $(get_current_dns 4); do
                yq -i ".network.config[$config_id].address += [\"$cur\"]" $ci_file
            done
        fi
        if $need_set_dns6; then
            for cur in $(get_current_dns 6); do
                yq -i ".network.config[$config_id].address += [\"$cur\"]" $ci_file
            done
        fi
        # 如果 network.config[$config_id] 没有 address，则删除，避免低版本 cloud-init 报错
        yq -i "del(.network.config[$config_id] | select(has(\"address\") | not))" $ci_file
    fi

    apk del "$(get_yq_name)"

    # 查看文件
    info "Cloud-init network config"
    cat -n $ci_file >&2
}

# 实测没用，生成的 machine-id 是固定的
# 而且 lightsail centos 9 模板 machine-id 也是相同的，显然相同 id 不是个问题
clear_machine_id() {
    os_dir=$1

    # https://www.freedesktop.org/software/systemd/man/latest/machine-id.html
    # gentoo 不会自动创建该文件
    echo uninitialized >$os_dir/etc/machine-id

    # https://build.opensuse.org/projects/Virtualization:Appliances:Images:openSUSE-Leap-15.5/packages/kiwi-templates-Minimal/files/config.sh?expand=1
    rm -f $os_dir/var/lib/systemd/random-seed
}

# 注意 anolis 7 有这个文件，可能干扰我们的配置?
# /etc/cloud/cloud.cfg.d/aliyun_cloud.cfg -> /sys/firmware/qemu_fw_cfg/by_name/etc/cloud-init/vendor-data/raw
download_cloud_init_config() {
    os_dir=$1
    recognize_static6=$2
    recognize_ipv6_types=$3

    ci_file=$os_dir/etc/cloud/cloud.cfg.d/99_fallback.cfg
    download $confhome/cloud-init.yaml $ci_file
    # 删除注释行，除了第一行
    sed -i '1!{/^[[:space:]]*#/d}' $ci_file

    # 修改密码
    # 不能用 sed 替换，因为含有特殊字符
    content=$(cat $ci_file)
    echo "${content//@PASSWORD@/$(get_password_linux_sha512)}" >$ci_file

    # 修改 ssh 端口
    if is_need_change_ssh_port; then
        sed -i "s/@SSH_PORT@/$ssh_port/g" $ci_file
    else
        sed -i "/@SSH_PORT@/d" $ci_file
    fi

    # swapfile
    # 如果分区表中已经有swapfile就跳过，例如arch
    if ! grep -w swap $os_dir/etc/fstab; then
        cat <<EOF >>$ci_file
swap:
  filename: /swapfile
  size: auto
EOF
    fi

    create_cloud_init_network_config "$ci_file" "$recognize_static6" "$recognize_ipv6_types"
}

get_image_state() {
    local os_dir=$1
    local image_state=

    # 如果 dd 镜像精简了 State.ini，则从注册表获取
    if state_ini=$(find_file_ignore_case $os_dir/Windows/Setup/State/State.ini); then
        image_state=$(grep -i '^ImageState=' $state_ini | cut -d= -f2 | tr -d '\r')
    fi
    if [ -z "$image_state" ]; then
        apk add hivex
        hive=$(find_file_ignore_case $os_dir/Windows/System32/config/SOFTWARE)
        image_state=$(hivexget $hive '\Microsoft\Windows\CurrentVersion\Setup\State' ImageState)
        apk del hivex
    fi

    if [ -n "$image_state" ]; then
        echo "$image_state"
    else
        error_and_exit "Cannot get ImageState."
    fi
}

get_axx64() {
    case "$(uname -m)" in
    x86_64) echo amd64 ;;
    aarch64) echo arm64 ;;
    esac
}

is_file_or_link() {
    # -e / -f 坏软连接，返回 false
    # -L 坏软连接，返回 true
    [ -f $1 ] || [ -L $1 ]
}

cp_resolv_conf() {
    os_dir=$1
    if is_file_or_link $os_dir/etc/resolv.conf &&
        ! is_file_or_link $os_dir/etc/resolv.conf.orig; then
        mv $os_dir/etc/resolv.conf $os_dir/etc/resolv.conf.orig
    fi
    cp -f /etc/resolv.conf $os_dir/etc/resolv.conf
}

rm_resolv_conf() {
    os_dir=$1
    rm -f $os_dir/etc/resolv.conf $os_dir/etc/resolv.conf.orig
}

restore_resolv_conf() {
    os_dir=$1
    if is_file_or_link $os_dir/etc/resolv.conf.orig; then
        mv -f $os_dir/etc/resolv.conf.orig $os_dir/etc/resolv.conf
    fi
}

keep_now_resolv_conf() {
    os_dir=$1
    rm -f $os_dir/etc/resolv.conf.orig
}

# 抄 https://github.com/alpinelinux/alpine-conf/blob/3.18.1/setup-disk.in#L421
get_alpine_firmware_pkgs() {
    # 需要有 modloop，不然 modinfo 会报错
    ensure_service_started modloop >&2

    # 如果不在单独的文件夹，则用 linux-firmware-other
    # 如果在单独的文件夹，则用 linux-firmware-xxx
    # 如果不需要 firmware，则用 linux-firmware-none
    firmware_pkgs=$(
        cd /sys/module && modinfo -F firmware -- * 2>/dev/null |
            awk -F/ '{print $1 == $0 ? "linux-firmware-other" : "linux-firmware-"$1}' |
            sort -u
    )

    # 使用 command 因为自己覆盖了 apk 添加了 >&2
    retry 5 command apk search --quiet --exact ${firmware_pkgs:-linux-firmware-none}
}

get_ucode_firmware_pkgs() {
    is_virt && return

    case "$distro" in
    centos | almalinux | rocky | oracle | redhat | anolis | opencloudos | openeuler) os=elol ;;
    *) os=$distro ;;
    esac

    case "$os-$(get_cpu_vendor)" in
    # alpine 的 linux-firmware 以文件夹进行拆分
    # setup-alpine 会自动安装需要的 firmware（modloop 没挂载则无效）
    # https://github.com/alpinelinux/alpine-conf/blob/3.18.1/setup-disk.in#L421
    alpine-intel) echo intel-ucode ;;
    alpine-amd) echo amd-ucode ;;
    alpine-*) ;;

    debian-intel) echo firmware-linux intel-microcode ;;
    debian-amd) echo firmware-linux amd64-microcode ;;
    debian-*) echo firmware-linux ;;

    ubuntu-intel) echo linux-firmware intel-microcode ;;
    ubuntu-amd) echo linux-firmware amd64-microcode ;;
    ubuntu-*) echo linux-firmware ;;

    # 无法同时安装 kernel-firmware kernel-firmware-intel
    opensuse-intel) echo kernel-firmware ucode-intel ;;
    opensuse-amd) echo kernel-firmware ucode-amd ;;
    opensuse-*) echo kernel-firmware ;;

    arch-intel) echo linux-firmware intel-ucode ;;
    arch-amd) echo linux-firmware amd-ucode ;;
    arch-*) echo linux-firmware ;;

    gentoo-intel) echo linux-firmware intel-microcode ;;
    gentoo-amd) echo linux-firmware ;;
    gentoo-*) echo linux-firmware ;;

    nixos-intel) echo linux-firmware microcodeIntel ;;
    nixos-amd) echo linux-firmware microcodeAmd ;;
    nixos-*) echo linux-firmware ;;

    fedora-intel) echo linux-firmware microcode_ctl ;;
    fedora-amd) echo linux-firmware amd-ucode-firmware microcode_ctl ;;
    fedora-*) echo linux-firmware microcode_ctl ;;

    elol-intel) echo linux-firmware microcode_ctl ;;
    elol-amd) echo linux-firmware microcode_ctl ;;
    elol-*) echo linux-firmware microcode_ctl ;;
    esac
}

chroot_systemctl_disable() {
    os_dir=$1
    shift

    for unit in "$@"; do
        # 如果传进来的是x(没有.) 则改成 x.service
        if ! [[ "$unit" = "*.*" ]]; then
            unit=$i.service
        fi

        # debian 10 返回值始终是 0
        if ! chroot $os_dir systemctl list-unit-files "$unit" 2>&1 | grep -Eq '^0 unit'; then
            chroot $os_dir systemctl disable "$unit"
        fi
    done
}

remove_cloud_init() {
    os_dir=$1

    if ! is_have_cmd_on_disk $os_dir cloud-init; then
        return
    fi

    info "Remove Cloud-Init"

    # 两种方法都可以
    if [ -d $os_dir/etc/cloud ]; then
        touch $os_dir/etc/cloud/cloud-init.disabled
    fi

    # systemctl is-enabled cloud-init-hotplugd.service 状态是 static
    # disable 会出现一堆提示信息，也无法 disable
    for unit in $(
        chroot $os_dir systemctl list-unit-files |
            grep -E '^(cloud-init-.*|cloud-config|cloud-final)\.(service|socket)' | grep enabled | awk '{print $1}'
    ); do
        # 服务不存在时会报错
        if chroot $os_dir systemctl -q is-enabled "$unit"; then
            chroot $os_dir systemctl disable "$unit"
        fi
    done

    # for pkg_mgr in dnf yum zypper apt-get; do
    #     if is_have_cmd_on_disk $os_dir $pkg_mgr; then
    #         case $pkg_mgr in
    #         dnf | yum)
    #             chroot $os_dir $pkg_mgr remove -y cloud-init
    #             rm -f $os_dir/etc/cloud/cloud.cfg.rpmsave
    #             ;;
    #         zypper)
    #             # 加上 -u 才会删除依赖
    #             chroot $os_dir zypper remove -y -u cloud-init
    #             ;;
    #         apt-get)
    #             # ubuntu 25.04 开始有 cloud-init-base
    #             chroot_apt_remove $os_dir cloud-init cloud-init-base
    #             chroot_apt_autoremove $os_dir
    #             ;;
    #         esac
    #         break
    #     fi
    # done
}

disable_jeos_firstboot() {
    os_dir=$1
    info "Disable JeOS Firstboot"

    # 两种方法都可以
    # https://github.com/openSUSE/jeos-firstboot?tab=readme-ov-file#usage

    rm -rf $os_dir/var/lib/YaST2/reconfig_system

    for name in jeos-firstboot jeos-firstboot-snapshot; do
        # 服务不存在时会报错
        chroot $os_dir systemctl disable "$name.service" 2>/dev/null || true
    done
}

create_network_manager_config() {
    source_cfg=$1
    os_dir=$2
    info "Create Network-Manager config"

    # 可以直接用 alpine 的 cloud-init 生成 Network Manager 配置
    apk add cloud-init
    cloud-init devel net-convert -p "$source_cfg" -k yaml -d /out -D alpine -O network-manager

    # 文档明确写了 ipv6.method=dhcp 无法获取网关
    # https://networkmanager.dev/docs/api/latest/nm-settings-nmcli.html#:~:text=false/no/off-,ipv6,-.method
    sed -i -e '/^may-fail=/d' -e 's/^method=dhcp/method=auto/' \
        /out/etc/NetworkManager/system-connections/cloud-init-eth*.nmconnection

    # 删除 # Generated by cloud-init. Changes will be lost.
    # 删除 org.freedesktop.NetworkManager.origin=cloud-init
    # 并删除头部的空行
    sed -i \
        -e '/^# Generated by cloud-init/d' \
        -e '/^org\.freedesktop\.NetworkManager\.origin=cloud-init/d' \
        /out/etc/NetworkManager/system-connections/cloud-init-eth*.nmconnection
    del_head_empty_lines_inplace /out/etc/NetworkManager/system-connections/cloud-init-eth*.nmconnection

    cp /out/etc/NetworkManager/system-connections/cloud-init-eth*.nmconnection \
        $os_dir/etc/NetworkManager/system-connections/

    # 清理
    rm -rf /out
    apk del cloud-init

    # 最终显示文件
    for file in "$os_dir"/etc/NetworkManager/system-connections/cloud-init-eth*.nmconnection; do
        cat -n "$file" >&2
    done
}

modify_linux() {
    os_dir=$1
    info "Modify Linux"

    find_and_mount() {
        mount_point=$1
        mount_dev=$(awk "\$2==\"$mount_point\" {print \$1}" $os_dir/etc/fstab)
        if [ -n "$mount_dev" ]; then
            mount $mount_dev $os_dir$mount_point
        fi
    }

    # 修复 onlink 网关
    add_onlink_script_if_need() {
        for ethx in $(get_eths); do
            if is_staticv4 || is_staticv6; then
                fix_sh=cloud-init-fix-onlink.sh
                download "$confhome/$fix_sh" "$os_dir/$fix_sh"
                insert_into_file "$ci_file" after '^runcmd:' <<EOF
  - bash "/$fix_sh" && rm -f "/$fix_sh"
EOF
                break
            fi
        done
    }

    # 部分镜像有默认配置，例如 centos
    del_exist_sysconfig_NetworkManager_config $os_dir

    # 仅 fedora (el/ol/国产fork 用的是复制文件方法)
    # 1. 禁用 selinux kdump
    # 2. 添加微码+固件
    if [ -f $os_dir/etc/redhat-release ]; then
        # 防止删除 cloud-init / 安装 firmware 时不够内存
        create_swap_if_ram_less_than 2048 $os_dir/swapfile

        find_and_mount /boot
        find_and_mount /boot/efi
        mount_pseudo_fs $os_dir
        cp_resolv_conf $os_dir

        # 可以直接用 alpine 的 cloud-init 生成 Network Manager 配置
        create_cloud_init_network_config /net.cfg
        create_network_manager_config /net.cfg "$os_dir"
        rm /net.cfg

        remove_cloud_init $os_dir

        disable_selinux $os_dir
        disable_kdump $os_dir

        if fw_pkgs=$(get_ucode_firmware_pkgs) && [ -n "$fw_pkgs" ]; then
            is_have_cmd_on_disk $os_dir dnf && mgr=dnf || mgr=yum
            chroot $os_dir $mgr install -y $fw_pkgs
        fi

        restore_resolv_conf $os_dir
    fi

    # debian
    # 1. EOL 换源
    # 2. 修复网络问题
    # 3. 添加微码+固件
    # 注意 ubuntu 也有 /etc/debian_version
    if [ "$distro" = debian ]; then
        # 修复 onlink 网关
        # add_onlink_script_if_need

        mount_pseudo_fs $os_dir
        cp_resolv_conf $os_dir
        find_and_mount /boot
        find_and_mount /boot/efi

        remove_cloud_init $os_dir

        # 获取当前开启的 Components, 后面要用
        if [ -f $os_dir/etc/apt/sources.list.d/debian.sources ]; then
            comps=$(grep ^Components: $os_dir/etc/apt/sources.list.d/debian.sources | head -1 | cut -d' ' -f2-)
        else
            comps=$(grep '^deb ' $os_dir/etc/apt/sources.list | head -1 | cut -d' ' -f4-)
        fi


        # non-ELTS
        if is_in_china; then
            # 不处理 security 源 security.debian.org/debian-security 和 /etc/apt/mirrors/debian-security.list
            for file in $os_dir/etc/apt/mirrors/debian.list $os_dir/etc/apt/sources.list; do
                if [ -f "$file" ]; then
                    sed -i "s|deb\.debian\.org/debian|$deb_mirror|" "$file"
                fi
            done
        fi

        # 标记所有内核为自动安装
        pkgs=$(chroot $os_dir apt-mark showmanual linux-image* linux-headers*)
        chroot $os_dir apt-mark auto $pkgs

        # 安装合适的内核
        kernel_package=$kernel
        # shellcheck disable=SC2046
        # 检测机器是否能用 cloud 内核
        if [[ "$kernel_package" = 'linux-image-cloud-*' ]] &&
            ! sh /can_use_cloud_kernel.sh "$xda" $(get_eths); then
            kernel_package=$(echo "$kernel_package" | sed 's/-cloud//')
        fi
        # 如果镜像自带内核跟最佳内核是同一种且有更新
        # 则 apt install 只会进行更新，不会将包设置成 manual
        # 需要再运行 apt install 才会将包设置成 manual
        chroot_apt_install $os_dir "$kernel_package"
        chroot_apt_install $os_dir "$kernel_package"

        # 使用 autoremove 删除非最佳内核
        chroot_apt_autoremove $os_dir

        # 微码+固件
        if fw_pkgs=$(get_ucode_firmware_pkgs) && [ -n "$fw_pkgs" ]; then
            #  debian 10 11 的 iucode-tool 在 contrib 里面
            #  debian 12 的 iucode-tool 在 main 里面
            [ "$releasever" -ge 12 ] &&
                comps_to_add=non-free-firmware ||
                comps_to_add="contrib non-free"

            if [ -f $os_dir/etc/apt/sources.list.d/debian.sources ]; then
                file=$os_dir/etc/apt/sources.list.d/debian.sources
                search='^[# ]*Components:'
            else
                file=$os_dir/etc/apt/sources.list
                search='^[# ]*deb'
            fi

            for c in $comps_to_add; do
                if ! echo "$comps" | grep -wq "$c"; then
                    sed -Ei "/$search/s/$/ $c/" $file
                fi
            done

            chroot_apt_install $os_dir $fw_pkgs
        fi

        # genericcloud 删除以下文件开机时才会显示 grub 菜单
        # https://salsa.debian.org/cloud-team/debian-cloud-images/-/tree/master/config_space/bookworm/files/etc/default/grub.d
        rm -f $os_dir/etc/default/grub.d/10_cloud.cfg
        rm -f $os_dir/etc/default/grub.d/15_timeout.cfg
        chroot $os_dir update-grub

        if true; then
            # 如果使用 nocloud 镜像
            chroot_apt_install $os_dir openssh-server
        else
            # 如果使用 genericcloud 镜像

            # 还原默认配置并创建 key
            # cat $os_dir/usr/share/openssh/sshd_config $os_dir/etc/ssh/sshd_config
            # chroot $os_dir ssh-keygen -A
            rm -rf $os_dir/etc/ssh/sshd_config
            UCF_FORCE_CONFFMISS=1 chroot $os_dir dpkg-reconfigure openssh-server
        fi

        # 镜像自带的网络管理器
        # debian 11 ifupdown
        # debian 12 netplan + networkd + resolved
        # ifupdown dhcp 不支持 24位掩码+不规则网关?

        # 强制使用 netplan
        if false && is_have_cmd_on_disk $os_dir netplan; then
            chroot_apt_install $os_dir netplan.io
            # 服务不存在时会报错
            chroot $os_dir systemctl disable networking resolvconf 2>/dev/null || true
            chroot $os_dir systemctl enable systemd-networkd systemd-resolved
            rm_resolv_conf $os_dir
            ln -sf ../run/systemd/resolve/stub-resolv.conf $os_dir/etc/resolv.conf
            if [ -f "$os_dir/etc/cloud/cloud.cfg.d/99_fallback.cfg" ]; then
                insert_into_file $os_dir/etc/cloud/cloud.cfg.d/99_fallback.cfg after '#cloud-config' <<EOF
system_info:
  network:
    renderers: [netplan]
    activators: [netplan]
EOF
            fi
        fi

        create_ifupdown_config $os_dir/etc/network/interfaces

        # ifupdown 不支持 rdnss
        # 但 iso 安装不会安装 rdnssd，而是在安装时读取 rdnss 并写入 resolv.conf
        if false; then
            chroot_apt_install $os_dir rdnssd
        fi

        # debian 10 11 云镜像安装了 resolvconf
        # debian 12 云镜像安装了 netplan systemd-resolved
        # 云镜像用了 cloud-init 自动配置网络，用户是无感的，因此官方云镜像可以随便选择网络管理器
        # 但我们的系统安装后用户可能有手动配置网络的需求，因此用回 iso 安装时的网络管理器 ifupdown

        # 服务不存在时会报错
        chroot $os_dir systemctl disable resolvconf systemd-networkd systemd-resolved 2>/dev/null || true

        chroot_apt_install $os_dir ifupdown
        chroot_apt_remove $os_dir resolvconf netplan.io systemd-resolved
        chroot_apt_autoremove $os_dir
        chroot $os_dir systemctl enable networking

        # 静态时 networking 服务不会根据 /etc/network/interfaces 更新 resolv.conf
        # 动态时使用了 isc-dhcp-client 支持自动更新 resolv.conf
        # 另外 debian iso 不会安装 rdnssd
        keep_now_resolv_conf $os_dir
    fi

    # opensuse
    # 1. kernel-default-base 缺少 nvme 驱动，换成 kernel-default
    # 2. 添加微码+固件
    # https://documentation.suse.com/smart/virtualization-cloud/html/minimal-vm/index.html
    if grep -q opensuse $os_dir/etc/os-release; then
        create_swap_if_ram_less_than 1024 $os_dir/swapfile
        mount_pseudo_fs $os_dir
        cp_resolv_conf $os_dir
        find_and_mount /boot
        find_and_mount /boot/efi

        disable_jeos_firstboot $os_dir

        # 16.0 需要安装 openssh
        if ! chroot $os_dir rpm -qi openssh-server; then
            chroot $os_dir zypper install -y openssh-server
        fi

        # 禁用 selinux
        disable_selinux $os_dir

        # opensuse leap 15.6 用 wicked
        # opensuse leap 16.0 / tumbleweed 用 NetworkManager
        if chroot $os_dir rpm -qi wicked; then
            # sysconfig ifcfg
            create_cloud_init_network_config $os_dir/net.cfg
            chroot $os_dir cloud-init devel net-convert \
                -p /net.cfg -k yaml -d out -D opensuse -O sysconfig

            # 删除
            # Created by cloud-init on instance boot automatically, do not edit.
            #
            sed -i '/^#/d' "$os_dir/out/etc/sysconfig/network/ifcfg-eth"*

            for ethx in $(get_eths); do
                # 1. 修复甲骨文云重启后 ipv6 丢失
                # https://github.com/openSUSE/wicked/issues/1058
                # 还要注意 wicked dhcpv6 获取到的 ipv6 是 /64，其他 DHCPv6 程序获取到的是 /128
                echo DHCLIENT6_USE_LAST_LEASE=no >>$os_dir/out/etc/sysconfig/network/ifcfg-$ethx

                # 2. 修复 onlink 网关
                for prefix in '' 'default '; do
                    if is_staticv4; then
                        get_netconf_to ipv4_gateway
                        echo "${prefix}${ipv4_gateway} - -" >>$os_dir/out/etc/sysconfig/network/ifroute-$ethx
                    fi
                    if is_staticv6; then
                        get_netconf_to ipv6_gateway
                        echo "${prefix}${ipv6_gateway} - -" >>$os_dir/out/etc/sysconfig/network/ifroute-$ethx
                    fi
                done
            done

            # 复制配置
            for file in \
                "$os_dir/out/etc/sysconfig/network/ifcfg-eth"* \
                "$os_dir/out/etc/sysconfig/network/ifroute-eth"*; do
                # 动态 ip 没有 ifroute-eth*
                if [ -f $file ]; then
                    cp $file $os_dir/etc/sysconfig/network/
                fi
            done

            # 清理
            rm -rf $os_dir/net.cfg $os_dir/out

        else
            # 如果使用 cloud-init 则需要 touch NetworkManager.conf
            # 更新到 cloud-init 24.1 后删除
            # touch $os_dir/etc/NetworkManager/NetworkManager.conf

            # 可以直接用 alpine 的 cloud-init 生成 Network Manager 配置
            create_cloud_init_network_config /net.cfg
            create_network_manager_config /net.cfg "$os_dir"
            rm /net.cfg
        fi

        # 选择新内核
        # 只有 leap 有 kernel-azure
        if grep -iq leap $os_dir/etc/os-release && [ "$(get_cloud_vendor)" = azure ]; then
            target_kernel='kernel-azure'
        else
            target_kernel='kernel-default'
        fi

        # rpm -qi 不支持通配符
        installed_kernel=$(chroot $os_dir rpm -qa 'kernel-*' --qf '%{NAME}\n' | grep -v firmware)
        if ! [ "$(echo "$installed_kernel" | wc -l)" -eq 1 ]; then
            error_and_exit "Unexpected kernel installed: $installed_kernel"
        fi

        # 15.6 / tumbleweed 自带的是 kernel-default-base
        # 16.0 自带的是 kernel-default
        # 不能同时装 kernel-default-base 和 kernel-default

        if ! [ "$installed_kernel" = "$target_kernel" ]; then
            chroot $os_dir zypper remove -y -u $installed_kernel

            # x86 必须设置一个密码，否则报错，arm 没有这个问题
            # Failed to get root password hash
            # Failed to import /etc/uefi/certs/76B6A6A0.crt
            # warning: %post(kernel-default-5.14.21-150500.55.83.1.x86_64) scriptlet failed, exit status 255
            if grep -q '^root:[:!*]' $os_dir/etc/shadow; then
                echo "root:$(mkpasswd '')" | chroot $os_dir chpasswd -e
                chroot $os_dir zypper install -y $target_kernel
                chroot $os_dir passwd -d root
            else
                chroot $os_dir zypper install -y $target_kernel
            fi
        fi

        # 固件+微码
        if fw_pkgs=$(get_ucode_firmware_pkgs) && [ -n "$fw_pkgs" ]; then
            chroot $os_dir zypper install -y $fw_pkgs
        fi

        # 最后才删除 cloud-init
        # 因为生成 sysconfig 网络配置要用目标系统的 cloud-init
        remove_cloud_init $os_dir

        restore_resolv_conf $os_dir
    fi

    basic_init $os_dir

    # 应该在这里是否运行了 basic_init 和创建了网络配置文件
    # 如果没有，则使用 cloud-init

    # 查看 cloud-init 最终配置
    if [ -f "$ci_file" ]; then
        cat -n "$ci_file"
    fi

    # 删除 swap
    swapoff -a
    rm -f $os_dir/swapfile
}

modify_os_on_disk() {
    only_process=$1
    info "Modify disk if is $only_process"

    update_part

    # dd linux 的时候不用修改硬盘内容
    if [ "$distro" = "dd" ] && ! lsblk -f /dev/$xda | grep ntfs; then
        return
    fi

    mkdir -p /os
    # 按分区容量大到小，依次寻找系统分区
    for part in $(lsblk /dev/$xda*[0-9] --sort SIZE -no NAME | tac); do
        # btrfs挂载的是默认子卷，如果没有默认子卷，挂载的是根目录
        # fedora 云镜像没有默认子卷，且系统在root子卷中
        if mount -o ro /dev/$part /os; then
            if [ "$only_process" = linux ]; then
                if etc_dir=$({ ls -d /os/etc/ || ls -d /os/*/etc/; } 2>/dev/null); then
                    os_dir=$(dirname $etc_dir)
                    # 重新挂载为读写
                    mount -o remount,rw /os
                    modify_linux $os_dir
                    return
                fi
            elif [ "$only_process" = windows ]; then
                # find 不是很聪明
                # find /mnt/c -iname windows -type d -maxdepth 1
                # find: /mnt/c/pagefile.sys: Permission denied
                # find: /mnt/c/swapfile.sys: Permission denied
                # shellcheck disable=SC1090
                # find_file_ignore_case 也在这个文件里面
                . <(wget -O- $confhome/windows-driver-utils.sh)
                if ntoskrnl_exe=$(find_file_ignore_case /os/Windows/System32/ntoskrnl.exe 2>/dev/null); then
                    # 其他地方会用到
                    is_windows() { true; }
                    # 重新挂载为读写、忽略大小写
                    umount /os
                    if ! { mount -t ntfs3 -o nocase,rw /dev/$part /os &&
                        mount | grep -w 'on /os type' | grep -wq rw; }; then
                        # 显示警告
                        warn "Can't normally mount windows partition /dev/$part as rw."
                        dmesg | grep -F "ntfs3($part):" || true
                        # 有可能 fallback 挂载成 ro, 因此先取消挂载
                        if mount | grep -wq 'on /os type'; then
                            umount /os
                        fi
                        # 尝试修复并强制挂载
                        apk add ntfs-3g-progs
                        ntfsfix /dev/$part
                        apk del ntfs-3g-progs
                        mount -t ntfs3 -o nocase,rw,force /dev/$part /os
                    fi
                    # 获取版本号，其他地方会用到
                    get_windows_version_from_dll "$ntoskrnl_exe"
                    modify_windows /os
                    return
                fi
            fi
            umount /os
        fi
    done
    error_and_exit "Can't find os partition."
}

get_need_swap_size() {
    need_ram=$1
    phy_ram=$(get_approximate_ram_size)

    if [ $need_ram -gt $phy_ram ]; then
        echo $((need_ram - phy_ram))
    else
        echo 0
    fi
}

create_swap_if_ram_less_than() {
    need_ram=$1
    swapfile=$2

    swapsize=$(get_need_swap_size $need_ram)
    if [ $swapsize -gt 0 ]; then
        create_swap $swapsize $swapfile
    fi
}

create_swap() {
    swapsize=$1
    swapfile=$2

    if ! grep $swapfile /proc/swaps; then
        # 用兼容 btrfs 的方式创建 swapfile
        truncate -s 0 $swapfile
        # 如果分区不支持 chattr +C 会显示错误但返回值是 0
        chattr +C $swapfile 2>/dev/null
        fallocate -l ${swapsize}M $swapfile
        chmod 0600 $swapfile
        mkswap $swapfile
        swapon $swapfile
    fi
}

set_ssh_keys_and_del_password() {
    os_dir=$1
    info 'set ssh keys'

    # 添加公钥
    (
        umask 077
        mkdir -p $os_dir/root/.ssh
        cat /configs/ssh_keys >$os_dir/root/.ssh/authorized_keys
    )

    # 删除密码
    chroot $os_dir passwd -d root
}

# 除了 alpine 都会用到
change_ssh_conf() {
    os_dir=$1
    key=$2
    value=$3
    sub_conf=$4

    if line="^$key .*" && grep -Exq "$line" $os_dir/etc/ssh/sshd_config; then
        # 如果 sshd_config 存在此 key（非注释状态），则替换
        sed -Ei "s/$line/$key $value/" $os_dir/etc/ssh/sshd_config
    elif {
        # arch 没有 /etc/ssh/sshd_config.d/ 文件夹
        # opensuse tumbleweed 没有 /etc/ssh/sshd_config
        #                       有 /etc/ssh/sshd_config.d/ 文件夹
        #                       有 /usr/etc/ssh/sshd_config
        grep -q 'Include.*/etc/ssh/sshd_config.d' $os_dir/etc/ssh/sshd_config ||
            grep -q '^Include.*/etc/ssh/sshd_config.d/' $os_dir/usr/etc/ssh/sshd_config
    } 2>/dev/null; then
        mkdir -p $os_dir/etc/ssh/sshd_config.d/
        echo "$key $value" >"$os_dir/etc/ssh/sshd_config.d/$sub_conf"
    else
        # 如果 sshd_config 存在此 key (无论是否已注释)，则替换，包括删除注释
        # 否则追加
        line="^#?$key .*"
        if grep -Exq "$line" $os_dir/etc/ssh/sshd_config; then
            sed -Ei "s/$line/$key $value/" $os_dir/etc/ssh/sshd_config
        else
            echo "$key $value" >>$os_dir/etc/ssh/sshd_config
        fi
    fi
}

allow_password_login() {
    os_dir=$1
    change_ssh_conf "$os_dir" PasswordAuthentication yes 01-PasswordAuthentication.conf
}

allow_root_password_login() {
    os_dir=$1

    change_ssh_conf "$os_dir" PermitRootLogin yes 01-permitrootlogin.conf
}

change_ssh_port() {
    os_dir=$1
    ssh_port=$2

    change_ssh_conf "$os_dir" Port "$ssh_port" 01-change-ssh-port.conf
}

change_root_password() {
    os_dir=$1

    info 'change root password'

    if is_password_plaintext; then
        pam_d=$os_dir/etc/pam.d

        [ -f $pam_d/chpasswd ] && has_pamd_chpasswd=true || has_pamd_chpasswd=false

        if $has_pamd_chpasswd; then
            cp $pam_d/chpasswd $pam_d/chpasswd.orig

            # cat /etc/pam.d/chpasswd
            # @include common-password

            # cat /etc/pam.d/chpasswd
            # #%PAM-1.0
            # auth       include      system-auth
            # account    include      system-auth
            # password   substack     system-auth
            # -password   optional    pam_gnome_keyring.so use_authtok
            # password   substack     postlogin

            # 通过 /etc/pam.d/chpasswd 找到 /etc/pam.d/system-auth 或者 /etc/pam.d/system-auth
            # 再找到有 password 和 pam_unix.so 的行，并删除 use_authtok，写入 /etc/pam.d/chpasswd
            files=$(grep -E '^(password|@include)' $pam_d/chpasswd | awk '{print $NF}' | sort -u)
            for file in $files; do
                if [ -f "$pam_d/$file" ] && line=$(grep ^password "$pam_d/$file" | grep -F pam_unix.so); then
                    echo "$line" | sed 's/use_authtok//' >$pam_d/chpasswd
                    break
                fi
            done
        fi

        # 分两行写，不然遇到错误不会终止
        plaintext=$(get_password_plaintext)
        echo "root:$plaintext" | chroot $os_dir chpasswd

        if $has_pamd_chpasswd; then
            mv $pam_d/chpasswd.orig $pam_d/chpasswd
        fi
    else
        echo "root:$(get_password_linux_sha512)" | chroot $os_dir chpasswd -e
    fi
}

disable_selinux() {
    os_dir=$1

    # https://access.redhat.com/solutions/3176
    # centos7 也建议将 selinux 开关写在 cmdline
    # grep selinux=0 /usr/lib/dracut/modules.d/98selinux/selinux-loadpolicy.sh
    #     warn "To disable selinux, add selinux=0 to the kernel command line."
    if [ -f $os_dir/etc/selinux/config ]; then
        sed -i 's/^SELINUX=enforcing/SELINUX=disabled/g' $os_dir/etc/selinux/config
    fi

    # opensuse 没有安装 grubby
    if is_have_cmd_on_disk $os_dir grubby; then
        # grubby 只处理 GRUB_CMDLINE_LINUX，不会处理 GRUB_CMDLINE_LINUX_DEFAULT
        # rocky 的 GRUB_CMDLINE_LINUX_DEFAULT 有 crashkernel=auto
        chroot $os_dir grubby --update-kernel ALL --args selinux=0

        # el7 上面那条 grubby 命令不能设置 /etc/default/grub
        sed -i 's/selinux=1/selinux=0/' $os_dir/etc/default/grub
    else
        # 有可能没有 selinux 参数，但现在的镜像没有这个问题
        # sed -Ei 's/[[:space:]]?(security|selinux|enforcing)=[^ ]*//g' $os_dir/etc/default/grub
        sed -i 's/selinux=1/selinux=0/' $os_dir/etc/default/grub

        # 如果需要用 snapshot 可以用 transactional-update grub.cfg
        chroot $os_dir grub2-mkconfig -o /boot/grub2/grub.cfg
    fi
}

disable_kdump() {
    os_dir=$1

    # grubby 只处理 GRUB_CMDLINE_LINUX，不会处理 GRUB_CMDLINE_LINUX_DEFAULT
    # rocky 的 GRUB_CMDLINE_LINUX_DEFAULT 有 crashkernel=auto

    # 新安装的内核依然有 crashkernel，好像是 bug
    # https://forums.rockylinux.org/t/how-do-i-remove-crashkernel-from-cmdline/13346
    # 验证过程
    # yum remove --oldinstallonly   # 删除旧内核
    # rm -rf /boot/loader/entries/* # 删除启动条目
    # yum reinstall kernel-core     # 重新安装新内核
    # cat /boot/loader/entries/*    # 依然有 crashkernel=1G-4G:192M,4G-64G:256M,64G-:512M

    chroot $os_dir grubby --update-kernel ALL --args crashkernel=no
    # el7 上面那条 grubby 命令不能设置 /etc/default/grub
    sed -i 's/crashkernel=[^ "]*/crashkernel=no/' $os_dir/etc/default/grub
    if chroot $os_dir systemctl -q is-enabled kdump; then
        chroot $os_dir systemctl disable kdump
    fi
}

download_qcow() {
    apk add qemu-img
    info "Download qcow2 image"

    mkdir -p /installer
    mount /dev/disk/by-label/installer /installer

    qcow_file=/installer/cloud_image.qcow2
    if [ -n "$img_type_warp" ]; then
        # 边下载边解压，单线程下载
        # 用官方 wget ，带进度条
        apk add wget
        wget $img -O- | pipe_extract >$qcow_file
    else
        # 多线程下载
        download "$img" "$qcow_file"
    fi
}

connect_qcow() {
    modprobe nbd nbds_max=1
    qemu-nbd -c /dev/nbd0 $qcow_file

    # 需要等待一下
    # https://github.com/canonical/cloud-utils/blob/main/bin/mount-image-callback
    while ! blkid /dev/nbd0; do
        echo "Waiting for qcow file to be mounted..."
        sleep 5
    done
}

disconnect_qcow() {
    if [ -f /sys/block/nbd0/pid ]; then
        qemu-nbd -d /dev/nbd0

        # 需要等待一下
        while fuser -sm $qcow_file; do
            echo "Waiting for qcow file to be unmounted..."
            sleep 5
        done
    fi
}

get_part_size_mb_for_file_size_b() {
    local file_b=$1
    local file_mb=$((file_b / 1024 / 1024))

    # ext4 默认参数下
    #  分区大小   可用大小   利用率
    #  100 MiB      86 MiB   86.0%
    #  200 MiB     177 MiB   88.5%
    #  500 MiB     454 MiB   90.8%
    #  512 MiB     476 MiB   92.9%
    # 1024 MiB     957 MiB   93.4%
    # 2000 MiB    1914 MiB   95.7%
    # 2048 MiB    1929 MiB   94.1% 这里反而下降了
    # 5120 MiB    4938 MiB   96.4%

    # 文件系统大约占用 5% 空间

    # 假设 1929M 的文件，计算得到需要创建 2031M 的分区
    # 但是实测 2048M 的分区才能存放 1929M 的文件
    # 因此预留不足 150M 时补够 150M
    local reserve_mb=$((file_mb * 100 / 95 - file_mb))
    if [ $reserve_mb -lt 150 ]; then
        reserve_mb=150
    fi

    part_mb=$((file_mb + reserve_mb))
    echo "File size:      $file_mb MiB" >&2
    echo "Part size need: $part_mb MiB" >&2
    echo $part_mb
}

get_cloud_image_part_size() {
    # 7
    # https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud-2211.qcow2c 400m

    # 8
    # https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/AlmaLinux-8-GenericCloud-latest.x86_64.qcow2 600m
    # https://download.rockylinux.org/pub/rocky/8/images/x86_64/Rocky-8-GenericCloud-Base.latest.x86_64.qcow2 1.8g
    # https://yum.oracle.com/templates/OracleLinux/OL8/u9/x86_64/OL8U9_x86_64-kvm-b219.qcow2 1g
    # https://rhel-8.10-x86_64-kvm.qcow2 1g

    # 9
    # https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2 1.2g
    # https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2 600m
    # https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2 600m
    # https://yum.oracle.com/templates/OracleLinux/OL9/u3/x86_64/OL9U3_x86_64-kvm-b220.qcow2 600m
    # https://rhel-9.4-x86_64-kvm.qcow2 900m

    # 10
    # https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2 900m

    # https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/cloud/nocloud_alpine-3.19.1-x86_64-uefi-cloudinit-r0.qcow2 200m
    # https://kali.download/cloud-images/current/kali-linux-2024.1-cloud-genericcloud-amd64.tar.xz 200m
    # https://download.opensuse.org/tumbleweed/appliances/openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2 300m
    # https://download.opensuse.org/distribution/leap/15.5/appliances/openSUSE-Leap-15.5-Minimal-VM.aarch64-Cloud.qcow2 300m
    # https://mirror.fcix.net/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2 400m
    # https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2 500m
    # https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2 500m
    # https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img 500m
    # https://gentoo.osuosl.org/experimental/amd64/openstack/gentoo-openstack-amd64-systemd-latest.qcow2 800m

    # openeuler 是 .qcow2.xz，要解压后才知道 qcow2 大小
    if [ "$distro" = openeuler ]; then
        # openeuler 20.03 3g
        if [ "$releasever" = 20.03 ]; then
            echo 3GiB
        else
            echo 2GiB
        fi
    elif size_bytes=$(get_http_file_size "$img"); then
        # 缩小 btrfs 需要写 qcow2 ，实测写入后只多了 1M，因此不用特殊处理
        echo "$(get_part_size_mb_for_file_size_b $size_bytes)MiB"
    else
        # 如果没获取到文件大小
        echo "Could not get cloud image size in http response." >&2
        echo 2GiB
    fi
}

chroot_dnf() {
    if is_have_cmd_on_disk /os/ dnf; then
        chroot /os/ dnf -y "$@"
    else
        chroot /os/ yum -y "$@"
    fi
}

chroot_apt_update() {
    os_dir=$1

    current_hash=$(cat $os_dir/etc/apt/sources.list $os_dir/etc/apt/sources.list.d/*.sources 2>/dev/null | md5sum)
    if ! [ "$saved_hash" = "$current_hash" ]; then
        chroot $os_dir apt-get update
        saved_hash="$current_hash"
    fi
}

chroot_apt_install() {
    os_dir=$1
    shift

    chroot_apt_update $os_dir
    DEBIAN_FRONTEND=noninteractive chroot $os_dir apt-get install -y "$@"
}

chroot_apt_remove() {
    os_dir=$1
    shift

    # minimal 镜像 删除 grub-pc 时会安装 grub-efi-amd64
    # 因此需要先更新索引
    chroot_apt_update $os_dir

    # 不能用 apt remove --purge -y xxx yyy
    # 因为如果索引里没有其中一个，会报错，另一个也不会删除
    local pkgs=
    for pkg in "$@"; do
        # apt list 会提示 WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
        # 但又不能用 apt-get list
        if chroot $os_dir apt list --installed "$pkg" | grep -q installed; then
            pkgs="$pkgs $pkg"
        fi
    done

    # 删除 resolvconf 时会弹出建议重启，因此添加 noninteractive
    DEBIAN_FRONTEND=noninteractive chroot $os_dir apt-get remove --purge --allow-remove-essential -y $pkgs
}

chroot_apt_autoremove() {
    os_dir=$1

    change_confs() {
        action=$1

        # 只有 16.04 有 01autoremove-kernels
        # 16.04 结束支持后删除
        for conf in 01autoremove 01autoremove-kernels; do
            file=$os_dir/etc/apt/apt.conf.d/$conf
            case "$action" in
            change)
                if [ -f $file ]; then
                    sed -i.orig 's/VersionedKernelPackages/x/; s/NeverAutoRemove/x/' $file
                fi
                ;;
            restore)
                if [ -f $file.orig ]; then
                    mv $file.orig $file
                fi
                ;;
            esac
        done
    }

    change_confs change
    DEBIAN_FRONTEND=noninteractive chroot $os_dir apt-get autoremove --purge -y
    change_confs restore
}

del_default_user() {
    os_dir=$1

    while read -r user; do
        if grep ^$user':\$' "$os_dir/etc/shadow"; then
            echo "Deleting user $user"
            chroot "$os_dir" userdel -rf "$user"
        fi
    done < <(grep -v nologin$ "$os_dir/etc/passwd" | cut -d: -f1 | grep -v root)
}

is_el7_family() {
    is_have_cmd_on_disk "$1" yum &&
        ! is_have_cmd_on_disk "$1" dnf
}

del_exist_sysconfig_NetworkManager_config() {
    os_dir=$1

    # 删除云镜像自带的 dhcp 配置，防止歧义
    rm -rf $os_dir/etc/NetworkManager/system-connections/*.nmconnection
    rm -rf $os_dir/etc/sysconfig/network-scripts/ifcfg-*

    # 1. 修复 cloud-init 添加了 IPV*_FAILURE_FATAL / may-fail=false
    #    甲骨文 dhcpv6 获取不到 IP 将视为 fatal，原有的 ipv4 地址也会被删除
    # 2. 修复 dhcpv6 下，ifcfg 添加了 IPV6_AUTOCONF=no 导致无法获取网关
    # 3. 修复 dhcpv6 下，NM method=dhcp 导致无法获取网关
    if false; then
        ci_file=$os_dir/etc/cloud/cloud.cfg.d/99_fallback.cfg

        insert_into_file $ci_file after '^runcmd:' <<EOF
  - sed -i '/^IPV[46]_FAILURE_FATAL=/d' /etc/sysconfig/network-scripts/ifcfg-* || true
  - sed -i '/^may-fail=/d' /etc/NetworkManager/system-connections/*.nmconnection || true
  - for f in /etc/sysconfig/network-scripts/ifcfg-*; do grep -q '^DHCPV6C=yes' "\$f" && sed -i '/^IPV6_AUTOCONF=no/d' "\$f"; done
  - sed -i 's/^method=dhcp/method=auto/' /etc/NetworkManager/system-connections/*.nmconnection || true
  - systemctl is-enabled NetworkManager && systemctl restart NetworkManager || true
EOF
    fi
}

install_fnos() {
    info "Install fnos"
    os_dir=/os

    # 官方安装调用流程
    # /etc/init.d/run_install.sh > trim-install > trim-grub

    # 挂载 /os
    mkdir -p /os
    mount /dev/$xda*2 /os

    # 下载并挂载 iso
    mkdir -p /os/installer /iso
    download "$iso" /os/installer/fnos.iso
    mount -o ro /os/installer/fnos.iso /iso

    # 解压 initrd
    apk add cpio
    initrd_dir=/os/installer/initrd_dir
    mkdir -p $initrd_dir
    (
        cd $initrd_dir
        zcat /iso/install.amd/initrd.gz | cpio -idm
    )
    apk del cpio

    # 获取挂载参数
    fstab_line_os=$(strings $initrd_dir/trim-install | grep -m1 '^UUID=%s / ')
    fstab_line_efi=$(strings $initrd_dir/trim-install | grep -m1 '^UUID=%s /boot/efi ')
    fstab_line_swapfile=$(strings $initrd_dir/trim-install | grep -m1 '^/swapfile none swap ')

    # 删除 initrd
    rm -rf $initrd_dir

    # 复制 trimfs.tgz 并删除 ISO 以获得更多空间
    echo "moving trimfs.tgz..."
    cp /iso/trimfs.tgz /os/installer
    umount /iso
    rm /os/installer/fnos.iso

    # 挂载 /os/boot/efi
    if is_efi; then
        mkdir -p /os/boot/efi
        mount -o "$(echo "$fstab_line_efi" | awk '{print $4}')" /dev/$xda*1 /os/boot/efi
    fi

    # 复制系统
    info "Extract fnos"
    apk add tar gzip pv
    pv -f /os/installer/trimfs.tgz | tar zxp --numeric-owner --xattrs-include='*.*' -C /os
    apk del tar gzip pv

    # 删除 installer (trimfs.tgz)
    rm -rf /os/installer

    # 挂载 proc sys dev
    mount_pseudo_fs /os

    # 更新 initrd
    # chroot $os_dir update-initramfs -u

    # 更改密码
    if is_need_set_ssh_keys; then
        set_ssh_keys_and_del_password $os_dir
    else
        change_root_password $os_dir
    fi

    # ssh root 登录，测试用
    if false; then
        allow_root_password_login $os_dir
        chroot $os_dir systemctl enable ssh
    fi

    # grub
    if is_efi; then
        chroot $os_dir grub-install --efi-directory=/boot/efi
        chroot $os_dir grub-install --efi-directory=/boot/efi --removable
    else
        chroot $os_dir grub-install /dev/$xda
    fi

    # grub tty
    ttys_cmdline=$(get_ttys console=)
    echo GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX $ttys_cmdline\" \
        >>$os_dir/etc/default/grub.d/tty.cfg
    chroot $os_dir update-grub

    # fstab
    {
        # /
        uuid=$(lsblk /dev/$xda*2 -no UUID)
        echo "$fstab_line_os" | sed "s/%s/$uuid/"

        # 官方安装器即使 swapfile 设为 0 也会有这行
        echo "$fstab_line_swapfile" | sed "s/%s/$uuid/"

        # /boot/efi
        if is_efi; then
            uuid=$(lsblk /dev/$xda*1 -no UUID)
            echo "$fstab_line_efi" | sed "s/%s/$uuid/"
        fi
    } >$os_dir/etc/fstab

    # 网卡配置
    create_cloud_init_network_config /net.cfg
    create_network_manager_config /net.cfg $os_dir
    rm /net.cfg

    # 修正网卡名
    add_fix_eth_name_systemd_service $os_dir

    # frpc
    add_frpc_systemd_service_if_need $os_dir
}

install_qcow_by_copy() {
    info "Install qcow2 by copy"

    modify_el_ol() {
        info "Modify el ol"
        os_dir=/os

        # resolv.conf
        cp_resolv_conf /os

        # 部分镜像有默认配置，例如 centos
        del_exist_sysconfig_NetworkManager_config /os

        # 删除镜像的默认账户，防止使用默认账户密码登录 ssh
        del_default_user /os

        # selinux kdump
        disable_selinux /os
        disable_kdump /os

        # el7 删除 machine-id 后不会自动重建
        clear_machine_id /os

        # firmware + microcode
        if fw_pkgs=$(get_ucode_firmware_pkgs) && [ -n "$fw_pkgs" ]; then
            chroot_dnf install $fw_pkgs
        fi

        # fstab 删除多余分区
        # almalinux/rocky 镜像有 boot 分区
        # oracle 镜像有 swap 分区
        sed -i '/[[:space:]]\/boot[[:space:]]/d' /os/etc/fstab
        sed -i '/[[:space:]]swap[[:space:]]/d' /os/etc/fstab

        # os_part 变量:
        # mapper/vg_main-lv_root
        # mapper/opencloudos-root

        # oracle/opencloudos 系统盘从 lvm 改成 uuid 挂载
        sed -i "s,/dev/$os_part,UUID=$os_part_uuid," /os/etc/fstab
        if ls /os/boot/loader/entries/*.conf 2>/dev/null; then
            # options root=/dev/mapper/opencloudos-root ro console=ttyS0,115200n8 no_timer_check net.ifnames=0 crashkernel=1800M-64G:256M,64G-128G:512M,128G-486G:768M,486G-972G:1024M,972G-:2048M rd.lvm.lv=opencloudos/root rhgb quiet
            sed -i "s,/dev/$os_part,UUID=$os_part_uuid," /os/boot/loader/entries/*.conf
        fi

        # oracle/opencloudos 移除 lvm cmdline
        chroot /os grubby --update-kernel ALL --remove-args "resume rd.lvm.lv"
        # el7 上面那条 grubby 命令不能设置 /etc/default/grub
        sed -i 's/rd.lvm.lv=[^ "]*//g' /os/etc/default/grub

        # fstab 添加 efi 分区
        if is_efi; then
            # centos/oracle 要创建efi条目
            if ! grep /boot/efi /os/etc/fstab; then
                efi_part_uuid=$(lsblk /dev/$xda*1 -no UUID)
                echo "UUID=$efi_part_uuid /boot/efi vfat $efi_mount_opts 0 0" >>/os/etc/fstab
            fi
        else
            # 删除 efi 条目
            sed -i '/[[:space:]]\/boot\/efi[[:space:]]/d' /os/etc/fstab
        fi

        remove_grub_conflict_files() {
            # bios 和 efi 转换前先删除

            # bios转efi出错
            # centos 和 oracle x86_64 镜像只有 bios 镜像，/boot/grub2/grubenv 是真身
            # 安装grub-efi时，grubenv 会改成指向efi分区grubenv软连接
            # 如果安装grub-efi前没有删除原来的grubenv，原来的grubenv将不变，新建的软连接将变成 grubenv.rpmnew
            # 后续grubenv的改动无法同步到efi分区，会造成grub2-setdefault失效

            # efi转bios出错
            # 如果是指向efi目录的软连接（例如el8），先删除它，否则 grub2-install 会报错
            rm -rf /os/boot/grub2/grubenv /os/boot/grub2/grub.cfg
        }

        # openeuler arm 镜像 grub.cfg 在 /os/grub.cfg，可能给外部的 grub 读取，我们用不到
        # centos7 有 grub1 的配置
        rm -rf /os/grub.cfg /os/boot/grub/grub.conf /os/boot/grub/menu.lst

        # 安装引导
        if is_efi; then
            # 只有centos 和 oracle x86_64 镜像没有efi，其他系统镜像已经从efi分区复制了文件
            if [ -z "$efi_part" ]; then
                remove_grub_conflict_files
                # openeuler 自带 grub2-efi-ia32，此时安装 grub2-efi 提示已经安装了 grub2-efi-ia32，不会继续安装 grub2-efi-x64
                [ "$(uname -m)" = x86_64 ] && arch=x64 || arch=aa64
                chroot_dnf install efibootmgr grub2-efi-$arch shim-$arch
            fi
        else
            # bios
            remove_grub_conflict_files
            chroot /os/ grub2-install /dev/$xda
        fi

        # blscfg 启动项
        # rocky/almalinux镜像是独立的boot分区，但我们不是
        # 因此要添加boot目录
        if ls /os/boot/loader/entries/*.conf 2>/dev/null &&
            ! grep -q 'initrd /boot/' /os/boot/loader/entries/*.conf; then

            sed -i -E 's,((linux|initrd) /),\1boot/,g' /os/boot/loader/entries/*.conf
        fi

        # grub-efi-x64 包里面有 /etc/grub2-efi.cfg
        # 指向 /boot/efi/EFI/xxx/grub.cfg 或 /boot/grub2/grub.cfg
        # 指向哪里哪里就是 grub2-mkconfig 应该生成文件的位置
        # grubby 也是靠 /etc/grub2-efi.cfg 定位 grub.cfg 的位置
        # openeuler 24.03 x64 aa64 指向的文件不同
        if is_efi; then
            grub_o_cfg=$(chroot /os readlink -f /etc/grub2-efi.cfg)
        else
            grub_o_cfg=/boot/grub2/grub.cfg
        fi

        # efi 分区 grub.cfg
        # https://github.com/rhinstaller/anaconda/blob/346b932a26a19b339e9073c049b08bdef7f166c3/pyanaconda/modules/storage/bootloader/efi.py#L198
        # https://github.com/rhinstaller/anaconda/commit/15c3b2044367d375db6739e8b8f419ef3e17cae7
        if is_efi && ! echo "$grub_o_cfg" | grep -q '/boot/efi/EFI'; then
            # oracle linux 文件夹是 redhat
            # shellcheck disable=SC2010
            distro_efi=$(cd /os/boot/efi/EFI/ && ls -d -- * | grep -Eiv BOOT)
            cat <<EOF >/os/boot/efi/EFI/$distro_efi/grub.cfg
search --no-floppy --fs-uuid --set=dev $os_part_uuid
set prefix=(\$dev)/boot/grub2
export \$prefix
configfile \$prefix/grub.cfg
EOF
        fi

        # 主 grub.cfg
        if ls /os/boot/loader/entries/*.conf >/dev/null 2>&1 &&
            chroot /os/ grub2-mkconfig --help | grep -q update-bls-cmdline; then
            chroot /os/ grub2-mkconfig -o "$grub_o_cfg" --update-bls-cmdline
        else
            chroot /os/ grub2-mkconfig -o "$grub_o_cfg"
        fi

        # 网络配置
        # el7/8 sysconfig
        # el9 network-manager
        if [ -f $os_dir/etc/sysconfig/network-scripts/ifup-eth ]; then
            # sysconfig
            info 'sysconfig'

            # anolis/openeuler/opencloudos 可能要安装 cloud-init
            # opencloudos 无法使用 chroot $os_dir command -v xxx
            # chroot: failed to run command ‘command’: No such file or directory
            # 注意还要禁用 cloud-init 服务
            if ! is_have_cmd_on_disk $os_dir cloud-init; then
                chroot_dnf install cloud-init
            fi

            # cloud-init 路径
            # /usr/lib/python2.7/site-packages/cloudinit/net/
            # /usr/lib/python3/dist-packages/cloudinit/net/
            # /usr/lib/python3.9/site-packages/cloudinit/net/

            # el7 不认识 static6，但可改成 static，作用相同
            recognize_static6=true
            if ls $os_dir/usr/lib/python*/*-packages/cloudinit/net/sysconfig.py 2>/dev/null &&
                ! grep -q static6 $os_dir/usr/lib/python*/*-packages/cloudinit/net/sysconfig.py; then
                recognize_static6=false
            fi

            # cloud-init 20.1 才支持以下配置
            # https://cloudinit.readthedocs.io/en/20.4/topics/network-config-format-v1.html#subnet-ip
            # https://cloudinit.readthedocs.io/en/21.1/topics/network-config-format-v1.html#subnet-ip
            # ipv6_dhcpv6-stateful: Configure this interface with dhcp6
            # ipv6_dhcpv6-stateless: Configure this interface with SLAAC and DHCP
            # ipv6_slaac: Configure address with SLAAC

            # el7 最新 cloud-init 版本
            # centos 7         19.4-7.0.5.el7_9.6  backport 了 ipv6_xxx
            # openeuler 20.03  19.4-15.oe2003sp4   backport 了 ipv6_xxx
            # anolis 7         19.1.17-1.0.1.an7   没有更新到 centos7 相同版本,也没 backport ipv6_xxx，坑

            # 最好还修改 ifcfg-eth* 的 IPV6_AUTOCONF
            # 但实测 anolis7 cloud-init dhcp6 不会生成 IPV6_AUTOCONF，因此暂时不管
            # https://www.redhat.com/zh/blog/configuring-ipv6-rhel-7-8
            recognize_ipv6_types=true
            if ls -d $os_dir/usr/lib/python*/*-packages/cloudinit/net/ 2>/dev/null &&
                ! grep -qr ipv6_slaac $os_dir/usr/lib/python*/*-packages/cloudinit/net/; then
                recognize_ipv6_types=false
            fi

            # 生成 cloud-init 网络配置
            create_cloud_init_network_config $os_dir/net.cfg "$recognize_static6" "$recognize_ipv6_types"

            # 转换成目标系统的网络配置
            chroot $os_dir cloud-init devel net-convert \
                -p /net.cfg -k yaml -d out -D rhel -O sysconfig
            cp $os_dir/out/etc/sysconfig/network-scripts/ifcfg-eth* $os_dir/etc/sysconfig/network-scripts/

            # 清理
            rm -rf $os_dir/net.cfg $os_dir/out

            # 删除 # Created by cloud-init on instance boot automatically, do not edit.
            # 修正网络配置问题并显示文件
            sed -i -e '/^IPV[46]_FAILURE_FATAL=/d' -e '/^#/d' $os_dir/etc/sysconfig/network-scripts/ifcfg-*
            for file in "$os_dir/etc/sysconfig/network-scripts/ifcfg-"*; do
                if grep -q '^DHCPV6C=yes' "$file"; then
                    sed -i '/^IPV6_AUTOCONF=no/d' "$file"
                fi
                cat -n "$file"
            done
        else
            # Network Manager
            info 'Network Manager'

            create_cloud_init_network_config /net.cfg
            create_network_manager_config /net.cfg "$os_dir"

            # 清理
            rm /net.cfg
        fi

        # 不删除可能网络管理器不会写入dns
        rm_resolv_conf /os
    }

    modify_ubuntu() {
        os_dir=/os
        info "Modify Ubuntu"

        cp_resolv_conf $os_dir

        # 关闭 os prober，因为 os prober 有时很慢
        cp $os_dir/etc/default/grub $os_dir/etc/default/grub.orig
        echo 'GRUB_DISABLE_OS_PROBER=true' >>$os_dir/etc/default/grub

        # 避免 do-release-upgrade 时自动执行 dpkg-reconfigure grub-xx 但是 efi/biosgrub 分区不存在而导致报错
        # shellcheck disable=SC2046
        # chroot_apt_remove $os_dir $(is_efi && echo 'grub-pc' || echo 'grub-efi*' 'shim*')
        # chroot_apt_autoremove $os_dir

        # 安装 mbr
        if ! is_efi; then
            if false; then
                # debconf-show grub-pc
                # 每次开机硬盘名字可能不一样，但是 debian netboot 安装后也是设置了 grub-pc/install_devices
                echo grub-pc grub-pc/install_devices multiselect /dev/$xda | chroot $os_dir debconf-set-selections # 22.04
                echo grub-pc grub-pc/cloud_style_installation boolean true | chroot $os_dir debconf-set-selections # 24.04
                chroot $os_dir dpkg-reconfigure -f noninteractive grub-pc
            else
                chroot $os_dir grub-install /dev/$xda
            fi
        fi

        # 自带内核：
        # 常规版本             generic
        # minimal 20.04/22.04 kvm      # 后台 vnc 无显示
        # minimal 24.04       virtual

        # debian cloud 内核不支持 ahci，ubuntu virtual 支持

        # 标记所有内核为自动安装
        # 注意排除 linux-base
        # 返回值始终为 0
        pkgs=$(chroot $os_dir apt-mark showmanual \
            linux-generic linux-virtual linux-kvm \
            linux-image* linux-headers*)
        chroot $os_dir apt-mark auto $pkgs

        # 安装最佳内核
        flavor=$(get_ubuntu_kernel_flavor)
        echo "Use kernel flavor: $flavor"
        # 如果镜像自带内核跟最佳内核是同一种且有更新
        # 则 apt install 只会进行更新，不会将包设置成 manual
        # 需要再运行 apt install 才会将包设置成 manual
        chroot_apt_install $os_dir "linux-image-$flavor"
        chroot_apt_install $os_dir "linux-image-$flavor"

        # 使用 autoremove 删除多余内核
        chroot_apt_autoremove $os_dir

        # 安装固件+微码
        if fw_pkgs=$(get_ucode_firmware_pkgs) && [ -n "$fw_pkgs" ]; then
            chroot_apt_install $os_dir $fw_pkgs
        fi

        # 网络配置
        # 18.04+ netplan
        if is_have_cmd_on_disk $os_dir netplan; then
            # 避免删除 cloud-init 后，minimal 镜像的 netplan.io 被 autoremove
            chroot $os_dir apt-mark manual netplan.io

            # 生成 cloud-init 网络配置
            create_cloud_init_network_config $os_dir/net.cfg

            # ubuntu 18.04 cloud-init 版本 23.1.2，因此不用处理 onlink

            # 如果不是输出到 / 则不会生成 50-cloud-init.yaml
            # 注意比较多了什么东西
            if false; then
                chroot $os_dir cloud-init devel net-convert \
                    -p /net.cfg -k yaml -d /out -D ubuntu -O netplan
                sed -Ei "/^[[:space:]]+set-name:/d" $os_dir/out/etc/netplan/50-cloud-init.yaml
                cp $os_dir/out/etc/netplan/50-cloud-init.yaml $os_dir/etc/netplan/

                # 清理
                rm -rf $os_dir/net.cfg $os_dir/out
            else
                chroot $os_dir cloud-init devel net-convert \
                    -p /net.cfg -k yaml -d / -D ubuntu -O netplan
                sed -Ei "/^[[:space:]]+set-name:/d" $os_dir/etc/netplan/50-cloud-init.yaml

                # 清理
                rm -rf $os_dir/net.cfg
            fi
        fi

        # 自带的 60-cloudimg-settings.conf 禁止了 PasswordAuthentication
        file=$os_dir/etc/ssh/sshd_config.d/60-cloudimg-settings.conf
        if [ -f $file ]; then
            sed -i '/^PasswordAuthentication/d' $file
            if [ -z "$(cat $file)" ]; then
                rm -f $file
            fi
        fi

        # 更改 efi 目录的 grub.cfg 写死的 fsuuid
        # 因为 24.04 fsuuid 对应 boot 分区
        efi_grub_cfg=$os_dir/boot/efi/EFI/ubuntu/grub.cfg
        if is_efi; then
            os_uuid=$(lsblk -rno UUID /dev/$xda*2)
            sed -Ei "s|[0-9a-f-]{36}|$os_uuid|i" $efi_grub_cfg

            # 24.04 移除 boot 分区后，需要添加 /boot 路径
            if grep "'/grub'" $efi_grub_cfg; then
                sed -i "s|'/grub'|'/boot/grub'|" $efi_grub_cfg
            fi
        fi

        # 处理 40-force-partuuid.cfg
        force_partuuid_cfg=$os_dir/etc/default/grub.d/40-force-partuuid.cfg
        if [ -e $force_partuuid_cfg ]; then
            if is_virt; then
                # 更改写死的 partuuid
                os_part_uuid=$(lsblk -rno PARTUUID /dev/$xda*2)
                sed -i "s/^GRUB_FORCE_PARTUUID=.*/GRUB_FORCE_PARTUUID=$os_part_uuid/" $force_partuuid_cfg
            else
                # 独服不应该使用 initrdless boot
                sed -i "/^GRUB_FORCE_PARTUUID=/d" $force_partuuid_cfg
            fi
        fi

        # 要重新生成 grub.cfg，因为
        # 1 我们删除了 boot 分区
        # 2 改动了 /etc/default/grub.d/40-force-partuuid.cfg
        chroot $os_dir update-grub

        # 还原 grub 配置（os prober）
        mv $os_dir/etc/default/grub.orig $os_dir/etc/default/grub

        # fstab
        # 24.04 镜像有boot分区，但我们不需要
        sed -i '/[[:space:]]\/boot[[:space:]]/d' $os_dir/etc/fstab
        if ! is_efi; then
            # bios 删除 efi 条目
            sed -i '/[[:space:]]\/boot\/efi[[:space:]]/d' $os_dir/etc/fstab
        fi

        restore_resolv_conf $os_dir
    }

    efi_mount_opts=$(
        case "$distro" in
        ubuntu) echo "umask=0077" ;;
        *) echo "defaults,uid=0,gid=0,umask=077,shortname=winnt" ;;
        esac
    )

    # yum/apt 安装软件时需要的内存总大小
    need_ram=$(
        case "$distro" in
        ubuntu) echo 1024 ;;
        *) echo 2048 ;;
        esac
    )

    connect_qcow

    # 镜像分区格式
    # centos/rocky/almalinux/rhel: xfs
    # oracle x86_64:          lvm + xfs
    # oracle aarch64 cloud:   xfs
    # alibaba cloud linux 3:  ext4

    is_lvm_image=false
    if lsblk -f /dev/nbd0p* | grep LVM2_member; then
        is_lvm_image=true
        apk add lvm2
        lvscan
        vg=$(pvs | grep /dev/nbd0p | awk '{print $2}')
        lvchange -ay "$vg"
    fi

    # TODO: 系统分区应该是最后一个分区
    # 选择最大分区
    os_part=$(lsblk /dev/nbd0p* --sort SIZE -no NAME,FSTYPE | grep -E 'ext4|xfs' | tail -1 | awk '{print $1}')
    efi_part=$(lsblk /dev/nbd0p* --sort SIZE -no NAME,PARTTYPE | grep -i "$EFI_UUID" | awk '{print $1}')
    # 排除前两个，再选择最大分区
    # almalinux9 boot 分区的类型不是规定的 uuid
    # openeuler boot 分区是 fat 格式
    boot_part=$(lsblk /dev/nbd0p* --sort SIZE -no NAME,FSTYPE | grep -E 'ext4|xfs|fat' | awk '{print $1}' |
        grep -vx "$os_part" | grep -vx "$efi_part" | tail -1 | awk '{print $1}')

    if $is_lvm_image; then
        os_part="mapper/$os_part"
    fi

    info "qcow2 Partitions"
    lsblk -f /dev/nbd0 -o +PARTTYPE
    echo "Part OS:   $os_part"
    echo "Part EFI:  $efi_part"
    echo "Part Boot: $boot_part"

    # 分区寻找方式
    # 系统/分区          cmdline:root  fstab:efi
    # rocky             LABEL=rocky   LABEL=EFI
    # ubuntu            PARTUUID      LABEL=UEFI
    # 其他el/ol         UUID           UUID

    # read -r os_part_uuid os_part_label < <(lsblk /dev/$os_part -no UUID,LABEL)
    os_part_uuid=$(lsblk /dev/$os_part -no UUID)
    os_part_label=$(lsblk /dev/$os_part -no LABEL)
    os_part_fstype=$(lsblk /dev/$os_part -no FSTYPE)

    if [ -n "$efi_part" ]; then
        efi_part_uuid=$(lsblk /dev/$efi_part -no UUID)
        efi_part_label=$(lsblk /dev/$efi_part -no LABEL)
    fi

    mkdir -p /nbd /nbd-boot /nbd-efi

    mount_nouuid() {
        case "$os_part_fstype" in
        ext4) mount "$@" ;;
        xfs) mount -o nouuid "$@" ;;
        esac
    }

    # 使用目标系统的格式化程序
    # centos8 如果用alpine格式化xfs，grub2-mkconfig和grub2里面都无法识别xfs分区
    mount_nouuid /dev/$os_part /nbd/
    mount_pseudo_fs /nbd/
    case "$os_part_fstype" in
    ext4) chroot /nbd mkfs.ext4 -F -L "$os_part_label" -U "$os_part_uuid" /dev/$xda*2 ;;
    xfs) chroot /nbd mkfs.xfs -f -L "$os_part_label" -m uuid=$os_part_uuid /dev/$xda*2 ;;
    esac
    umount -R /nbd/

    # TODO: ubuntu 镜像缺少 mkfs.fat/vfat/dosfstools? initrd 不需要检查fs完整性？

    # 创建并挂载 /os
    mkdir -p /os
    mount -o noatime /dev/$xda*2 /os/

    # 如果是 efi 则创建 /os/boot/efi
    # 如果镜像有 efi 分区也创建 /os/boot/efi，用于复制 efi 分区的文件
    if is_efi || [ -n "$efi_part" ]; then
        mkdir -p /os/boot/efi/

        # 挂载 /os/boot/efi
        # 预先挂载 /os/boot/efi 因为可能 boot 和 efi 在同一个分区（openeuler 24.03 arm）
        # 复制 boot 时可以会复制 efi 的文件
        if is_efi; then
            mount -o $efi_mount_opts /dev/$xda*1 /os/boot/efi/
        fi
    fi

    # 复制系统分区
    echo Copying os partition...
    mount_nouuid -o ro /dev/$os_part /nbd/
    cp -a /nbd/* /os/
    umount /nbd/

    # 复制boot分区，如果有
    if [ -n "$boot_part" ]; then
        echo Copying boot partition...
        mount_nouuid -o ro /dev/$boot_part /nbd-boot/
        cp -a /nbd-boot/* /os/boot/
        umount /nbd-boot/
    fi

    # 复制efi分区，如果有
    if [ -n "$efi_part" ]; then
        echo Copying efi partition...
        mount -o ro /dev/$efi_part /nbd-efi/
        cp -a /nbd-efi/* /os/boot/efi/
        umount /nbd-efi/
    fi

    # 断开 qcow 并删除 qemu-img
    info "Disconnecting qcow2"
    if is_have_cmd vgchange; then
        vgchange -an
        apk del lvm2
    fi
    disconnect_qcow
    apk del qemu-img

    # 取消挂载硬盘
    info "Unmounting disk"
    if is_efi; then
        umount /os/boot/efi/
    fi
    umount /os/
    umount /installer/

    # 如果镜像有efi分区，复制其uuid
    # 如果有相同uuid的fat分区，则无法挂载
    # 所以要先复制efi分区，断开nbd再复制uuid
    # 复制uuid前要取消挂载硬盘 efi 分区
    if is_efi && [ -n "$efi_part_uuid" ]; then
        info "Copy efi partition uuid"
        apk add mtools
        mlabel -N "$(echo $efi_part_uuid | sed 's/-//')" -i /dev/$xda*1 ::$efi_part_label
        apk del mtools
        update_part
    fi

    # 删除 installer 分区并扩容
    info "Delete installer partition"
    apk add parted
    parted /dev/$xda -s -- rm 3
    update_part
    resize_after_install_cloud_image

    # 重新挂载 /os /boot/efi
    info "Re-mount disk"
    mount -o noatime /dev/$xda*2 /os/
    if is_efi; then
        mount -o $efi_mount_opts /dev/$xda*1 /os/boot/efi/
    fi

    # 创建 swap
    create_swap_if_ram_less_than $need_ram /os/swapfile

    # 挂载伪文件系统
    mount_pseudo_fs /os/

    case "$distro" in
    ubuntu) modify_ubuntu ;;
    *) modify_el_ol ;;
    esac

    # 基本配置
    basic_init /os

    # 最后才删除 cloud-init
    # 因为生成 netplan/sysconfig 网络配置要用目标系统的 cloud-init
    remove_cloud_init /os

    # 删除 swapfile
    swapoff -a
    rm -f /os/swapfile
}

get_partition_table_format() {
    apk add parted
    parted "$1" -s print | grep 'Partition Table:' | awk '{print $NF}'
}

dd_qcow() {
    info "DD qcow2"

    if true; then
        connect_qcow

        partition_table_format=$(get_partition_table_format /dev/nbd0)
        orig_nbd_virtual_size=$(get_disk_size /dev/nbd0)

        # 检查最后一个分区是否是 btrfs
        # 即使awk结果为空，返回值也是0，加上 grep . 检查是否结果为空
        if part_num=$(parted /dev/nbd0 -s print | awk NF | tail -1 | grep btrfs | awk '{print $1}' | grep .); then
            apk add btrfs-progs
            mkdir -p /mnt/btrfs
            mount /dev/nbd0p$part_num /mnt/btrfs

            # 回收空数据块
            btrfs device usage /mnt/btrfs
            btrfs balance start -dusage=0 /mnt/btrfs
            btrfs device usage /mnt/btrfs

            # 计算可以缩小的空间
            free_bytes=$(btrfs device usage /mnt/btrfs -b | grep Unallocated: | awk '{print $2}')
            reserve_bytes=$((100 * 1024 * 1024)) # 预留 100M 可用空间
            skrink_bytes=$((free_bytes - reserve_bytes))

            if [ $skrink_bytes -gt 0 ]; then
                # 缩小文件系统
                btrfs filesystem resize -$skrink_bytes /mnt/btrfs
                # 缩小分区
                part_start=$(parted /dev/nbd0 -s 'unit b print' | awk "\$1==$part_num {print \$2}" | sed 's/B//')
                part_size=$(btrfs filesystem usage /mnt/btrfs -b | grep 'Device size:' | awk '{print $3}')
                part_end=$((part_start + part_size - 1))
                umount /mnt/btrfs
                printf "yes" | parted /dev/nbd0 resizepart $part_num ${part_end}B ---pretend-input-tty

                # 缩小 qcow2
                disconnect_qcow
                qemu-img resize --shrink $qcow_file $((part_end + 1))

                # 重新连接
                connect_qcow
            else
                umount /mnt/btrfs
            fi
        fi

        # 显示分区
        lsblk -o NAME,SIZE,FSTYPE,LABEL /dev/nbd0

        # 将前1M dd到内存
        dd if=/dev/nbd0 of=/first-1M bs=1M count=1

        # 将1M之后 dd到硬盘
        # shellcheck disable=SC2194
        case 3 in
        1)
            # BusyBox dd
            dd if=/dev/nbd0 of=/dev/$xda bs=1M skip=1 seek=1
            ;;
        2)
            # 用原版 dd status=progress，但没有进度和剩余时间
            apk add coreutils
            dd if=/dev/nbd0 of=/dev/$xda bs=1M skip=1 seek=1 status=progress
            ;;
        3)
            # 用 pv
            apk add pv
            echo "Start DD Cloud Image..."
            pv -f /dev/nbd0 | dd of=/dev/$xda bs=1M skip=1 seek=1 iflag=fullblock
            ;;
        esac

        disconnect_qcow
    else
        # 将前1M dd到内存，将1M之后 dd到硬盘
        qemu-img dd if=$qcow_file of=/first-1M bs=1M count=1
        qemu-img dd if=$qcow_file of=/dev/disk/by-label/os bs=1M skip=1
    fi

    # 已 dd 并断开连接 qcow，可删除 qemu-img
    apk del qemu-img

    # 将前1M从内存 dd 到硬盘
    umount /installer/
    dd if=/first-1M of=/dev/$xda
    rm -f /first-1M

    # gpt 分区表开头记录了备份分区表的位置
    # 如果 qcow2 虚拟容量 大于 实际硬盘容量
    # 备份分区表的位置 将超出实际硬盘容量的大小
    # partprobe 会报错
    # Error: Invalid argument during seek for read on /dev/vda
    # parted 也无法正常工作
    # 需要提前修复分区表

    # 目前只有这个例子，因为其他 qcow2 虚拟容量最多 5g，是设定支持的容量
    # openSUSE-Leap-15.5-Minimal-VM.x86_64-kvm-and-xen.qcow2 容量是 25g
    # 缩小 btrfs 分区后 dd 到 10g 的机器上
    # 备份分区表的位置是 25g
    # 需要修复到 10g 的位置上
    # 否则 partprobe parted 都无法正常工作

    # 仅这种情况才用 sgdisk 修复
    if [ "$partition_table_format" = gpt ] &&
        [ "$orig_nbd_virtual_size" -gt "$(get_disk_size /dev/$xda)" ]; then
        fix_gpt_backup_partition_table_by_sgdisk
    fi
    update_part
}

fix_gpt_backup_partition_table_by_sgdisk() {
    # 当备份分区表超出实际硬盘容量时，只能用 sgdisk 修复分区表
    # 应用场景：镜像大小超出硬盘实际硬盘，但缩小分区后不超出实际硬盘容量，可以顺利 DD
    # 例子 openSUSE-Leap-15.5-Minimal-VM.x86_64-kvm-and-xen.qcow2

    # parted 无法修复
    # parted /dev/$xda -f -s print

    # fdisk/sfdisk 显示主分区表损坏
    # echo write | sfdisk /dev/$xda
    # GPT PMBR size mismatch (50331647 != 20971519) will be corrected by write.
    # The primary GPT table is corrupt, but the backup appears OK, so that will be used.

    # 除此之外的场景应该用 parted 来修复

    apk add sgdisk

    # 两种方法都可以，但都不会修复备份分区表的 GUID
    # 此时 sgdisk -v /dev/vda 会提示主副分区表 guid 不相同
    # localhost:~# sgdisk -v /dev/$xda
    # Problem: main header's disk GUID (A24485F3-2C02-43BD-BF4E-F52E42B00DEA) doesn't
    # match the backup GPT header's disk GUID (ADAF57BC-B4F5-4E04-BCBA-BDDCD796C388)
    # You should use the 'b' or 'd' option on the recovery & transformation menu to
    # select one or the other header.
    if false; then
        sgdisk --backup /gpt-partition-table /dev/$xda
        sgdisk --load-backup /gpt-partition-table /dev/$xda
    else
        sgdisk --move-second-header /dev/$xda
    fi

    # 因此需要运行一次设置 guid
    if new_guid=$(sgdisk -v /dev/$xda | grep GUID | head -1 | grep -Eo '[0-9A-F-]{36}'); then
        sgdisk --disk-guid $new_guid /dev/$xda
    fi

    update_part

    apk del sgdisk
}

# 适用于 DD 后修复 gpt 备份分区表
fix_gpt_backup_partition_table_by_parted() {
    apk add parted
    parted /dev/$xda -f -s print
    update_part
}

resize_after_install_cloud_image() {
    # 提前扩容
    # 1 修复 vultr 512m debian 11 generic/genericcloud 首次启动 kernel panic
    # 2 防止 gentoo 云镜像 websync 时空间不足
    info "Resize after dd"
    lsblk -f /dev/$xda

    # 打印分区表，并自动修复备份分区表
    fix_gpt_backup_partition_table_by_parted

    disk_size=$(get_disk_size /dev/$xda)
    disk_end=$((disk_size - 1))

    # 不能漏掉最后的 _ ，否则第6部分都划到给 last_part_fs
    IFS=: read -r last_part_num _ last_part_end _ last_part_fs _ \
        < <(parted -msf /dev/$xda 'unit b print' | tail -1)
    last_part_end=$(echo $last_part_end | sed 's/B//')

    if [ $((disk_end - last_part_end)) -ge 0 ]; then
        printf "yes" | parted /dev/$xda resizepart $last_part_num 100% ---pretend-input-tty
        update_part

        mkdir -p /os

        # lvm ?
        # 用 cloud-utils-growpart？
        case "$last_part_fs" in
        ext4)
            # debian ci
            apk add e2fsprogs-extra
            e2fsck -p -f /dev/$xda*$last_part_num
            resize2fs /dev/$xda*$last_part_num
            apk del e2fsprogs-extra
            ;;
        xfs)
            # opensuse ci
            apk add xfsprogs-extra
            mount /dev/$xda*$last_part_num /os
            xfs_growfs /dev/$xda*$last_part_num
            umount /os
            apk del xfsprogs-extra
            ;;
        btrfs)
            # fedora ci
            apk add btrfs-progs
            mount /dev/$xda*$last_part_num /os
            btrfs filesystem resize max /os
            umount /os
            apk del btrfs-progs
            ;;
        ntfs)
            # windows dd
            apk add ntfs-3g-progs
            echo y | ntfsresize /dev/$xda*$last_part_num
            ntfsfix -d /dev/$xda*$last_part_num
            apk del ntfs-3g-progs
            ;;
        esac
        update_part
        parted /dev/$xda -s print
    fi
}

mount_part_basic_layout() {
    os_dir=$1
    efi_dir=$2

    if is_efi || is_xda_gt_2t; then
        os_part_num=2
    else
        os_part_num=1
    fi

    # 挂载系统分区
    mkdir -p $os_dir
    mount -t ext4 /dev/${xda}*${os_part_num} $os_dir

    # 挂载 efi 分区
    if is_efi; then
        mkdir -p $efi_dir
        mount -t vfat -o umask=077 /dev/${xda}*1 $efi_dir
    fi
}

mount_part_for_iso_installer() {
    info "Mount part for iso installer"

    if [ "$distro" = windows ]; then
        mount_args="-t ntfs3 -o nocase"
    else
        mount_args=
    fi

    # 挂载主分区
    mkdir -p /os
    mount $mount_args /dev/disk/by-label/os /os

    # 挂载其他分区
    if is_efi; then
        mkdir -p /os/boot/efi
        mount /dev/disk/by-label/efi /os/boot/efi
    fi
    mkdir -p /os/installer
    mount $mount_args /dev/disk/by-label/installer /os/installer
}

# virt-what 要用最新版
# vultr 1G High Frequency LAX 实际上是 kvm
# debian 11 virt-what 1.19 显示为 hyperv qemu
# debian 11 systemd-detect-virt 显示为 microsoft
# alpine virt-what 1.25 显示为 kvm
# 所以不要在原系统上判断具体虚拟化环境

# lscpu 也可查看虚拟化环境，但 alpine on lightsail 运行结果为 Microsoft
# 猜测 lscpu 只参考了 cpuid 没参考 dmi
# virt-what 可能会输出多行结果，因此用 grep

is_nt_ver_ge() {
    local orig sorted
    orig=$(printf '%s\n' "$1" "$nt_ver")
    sorted=$(echo "$orig" | sort -V)
    [ "$orig" = "$sorted" ]
}

get_cloud_vendor() {
    # busybox blkid 不显示 sr0 的 UUID
    apk add lsblk

    # http://git.annexia.org/?p=virt-what.git;a=blob;f=virt-what.in;hb=HEAD
    # virt-what 可识别厂商 aws google_cloud alibaba_cloud alibaba_cloud-ebm
    if is_dmi_contains "Amazon EC2" || is_virt_contains aws; then
        echo aws
    elif is_dmi_contains "Google Compute Engine" || is_dmi_contains "GoogleCloud" || is_virt_contains google_cloud; then
        echo gcp
    elif is_dmi_contains "OracleCloud"; then
        echo oracle
    elif is_dmi_contains "7783-7084-3265-9085-8269-3286-77"; then
        echo azure
    elif lsblk -o UUID,LABEL | grep -i 9796-932E | grep -iq config-2; then
        echo ibm
    elif is_dmi_contains 'Huawei Cloud'; then
        echo huawei
    elif is_dmi_contains 'Alibaba Cloud'; then
        echo aliyun
    elif is_dmi_contains 'Tencent Cloud'; then
        echo qcloud
    fi
}

get_filesize_mb() {
    du -m "$1" | awk '{print $1}'
}

is_absolute_path() {
    # 检查路径是否以/开头
    # 注意语法和 bash 不同
    [[ "$1" = "/*" ]]
}

# 注意使用方法是 list=$(list_add "$list" "$item_to_add")
list_add() {
    local list=$1
    local item_to_add=$2
    if [ -n "$list" ]; then
        echo "$list"
    fi
    echo "$item_to_add"
}

is_list_has() {
    local list=$1
    local item=$2
    echo "$list" | grep -qFx "$item"
}

# hivexget 是 shell 脚本，开头是 #!/bin/bash
# 但 alpine 没安装 bash，直接运行 hivexget 会报错
hivexget() {
    ash "$(which hivexget)" "$@"
}

# 添加 netboot.efi 备用
download_netboot_xyz_efi() {
    dir=$1
    info "download netboot.xyz.efi"

    file=$dir/netboot.xyz.efi
    if [ "$(uname -m)" = aarch64 ]; then
        download https://boot.netboot.xyz/ipxe/netboot.xyz-arm64.efi $file
    else
        download https://boot.netboot.xyz/ipxe/netboot.xyz.efi $file
    fi
}

refind_main_disk() {
    if true; then
        apk add sfdisk
        main_disk=$(sfdisk --disk-id /dev/$xda | sed 's/0x//')
    else
        apk add lsblk
        # main_disk=$(blkid --match-tag PTUUID -o value /dev/$xda)
        main_disk=$(lsblk --nodeps -rno PTUUID /dev/$xda)
    fi
}

sync_time() {
    if false; then
        # arm要手动从硬件同步时间，避免访问https出错
        # do 机器第二次运行会报错
        hwclock -s || true
    fi

    # ntp 时间差太多会无法同步？
    # http 时间可能不准确，毕竟不是专门的时间服务器
    #      也有可能没有 date header?
    method=http

    case "$method" in
    ntp)
        if is_in_china; then
            ntp_server=ntp.aliyun.com
        else
            ntp_server=pool.ntp.org
        fi
        # -d[d]   Verbose
        # -n      Run in foreground
        # -q      Quit after clock is set
        # -p      PEER
        ntpd -d -n -q -p "$ntp_server"
        ;;
    http)
        url="$(grep -m1 ^http /etc/apk/repositories)/$(uname -m)/APKINDEX.tar.gz"
        # 可能有多行，取第一行
        date_header=$(wget -S --no-check-certificate --spider "$url" 2>&1 | grep -m1 '^  Date:')
        # gnu date 不支持 -D
        busybox date -u -D "  Date: %a, %d %b %Y %H:%M:%S GMT" -s "$date_header"
        ;;
    esac

    # 重启时 alpine 会自动写入到硬件时钟，因此这里跳过
    # hwclock -w
}

is_ubuntu_lts() {
    IFS=. read -r major minor < <(echo "$releasever")
    [ $((major % 2)) = 0 ] && [ $minor = 04 ]
}

get_ubuntu_kernel_flavor() {
    # 20.04/22.04 kvm 内核 vnc 没显示
    # 24.04 kvm = virtual
    # linux-image-virtual = linux-image-6.x-generic
    # linux-image-generic = linux-image-6.x-generic + amd64-microcode + intel-microcode + linux-firmware + linux-modules-extra-generic

    # TODO: ISO virtual-hwe-24.04 不安装 linux-image-extra-virtual-hwe-24.04 不然会花屏

    # https://github.com/systemd/systemd/blob/main/src/basic/virt.c
    # https://github.com/canonical/cloud-init/blob/main/tools/ds-identify
    # http://git.annexia.org/?p=virt-what.git;a=blob;f=virt-what.in;hb=HEAD

    # 这里有坑
    # $(get_cloud_vendor) 调用了 cache_dmi_and_virt
    # 但是 $(get_cloud_vendor) 运行在 subshell 里面
    # subshell 运行结束后里面的变量就消失了
    # 因此先运行 cache_dmi_and_virt
    cache_dmi_and_virt
    vendor="$(get_cloud_vendor)"
    case "$vendor" in
    aws | gcp | oracle | azure | ibm) echo $vendor ;;
    *)
        suffix=
        if is_virt; then
            echo virtual$suffix
        else
            echo generic$suffix
        fi
        ;;
    esac
}

install_redhat_ubuntu() {
    info "Download iso installer"

    # 安装 grub2
    if is_efi; then
        # 注意低版本的grub无法启动f38 arm的内核
        # https://forums.fedoraforum.org/showthread.php?330104-aarch64-pxeboot-vmlinuz-file-format-changed-broke-PXE-installs
        apk add grub-efi efibootmgr
        grub-install --efi-directory=/os/boot/efi --boot-directory=/os/boot
    else
        apk add grub-bios
        grub-install --boot-directory=/os/boot /dev/$xda
    fi

    # 重新整理 extra，因为grub会处理掉引号，要重新添加引号
    extra_cmdline=''
    for var in $(grep -o '\bextra_[^ ]*' /proc/cmdline | xargs); do
        if [[ "$var" = "extra_main_disk=*" ]]; then
            # 重新记录主硬盘
            refind_main_disk
            extra_cmdline="$extra_cmdline extra_main_disk=$main_disk"
        else
            extra_cmdline="$extra_cmdline $(echo $var | sed -E "s/(extra_[^=]*)=(.*)/\1='\2'/")"
        fi
    done

    # 安装红帽系时，只有最后一个有安装界面显示
    # https://anaconda-installer.readthedocs.io/en/latest/boot-options.html#console
    console_cmdline=$(get_ttys console=)
    grub_cfg=/os/boot/grub/grub.cfg

    # 新版grub不区分linux/linuxefi
    # shellcheck disable=SC2154
    if [ "$distro" = "ubuntu" ]; then
        download $iso /os/installer/ubuntu.iso
        mkdir -p /iso
        mount -o ro /os/installer/ubuntu.iso /iso

        # 内核风味
        kernel=$(get_ubuntu_kernel_flavor)

        # 要安装的版本
        # https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html#id
        # 20.04 不能选择 minimal ，也没有 install-sources.yaml
        source_id=
        if [ -f /iso/casper/install-sources.yaml ]; then
            ids=$(grep id: /iso/casper/install-sources.yaml | awk '{print $2}')
            if [ "$(echo "$ids" | wc -l)" = 1 ]; then
                source_id=$ids
            else
                [ "$minimal" = 1 ] && v= || v=-v
                source_id=$(echo "$ids" | grep $v '\-minimal')

                if [ "$(echo "$source_id" | wc -l)" -gt 1 ]; then
                    error_and_exit "find multi source id."
                fi
            fi
        fi

        # 正常写法应该是 ds="nocloud-net;s=https://xxx/" 但是甲骨文云的ds更优先，自己的ds根本无访问记录
        # $seed 是 https://xxx/
        cat <<EOF >$grub_cfg
        set timeout=5
        menuentry "reinstall" {
            # https://bugs.launchpad.net/ubuntu/+source/grub2/+bug/1851311
            # rmmod tpm
            insmod all_video
            search --no-floppy --label --set=root installer
            loopback loop /ubuntu.iso
            linux (loop)/casper/vmlinuz iso-scan/filename=/ubuntu.iso autoinstall noprompt noeject cloud-config-url=$ks $extra_cmdline extra_kernel=$kernel extra_source_id=$source_id --- $console_cmdline
            initrd (loop)/casper/initrd
        }
EOF
    else
        download $vmlinuz /os/vmlinuz
        download $initrd /os/initrd.img
        download $squashfs /os/installer/install.img

        cat <<EOF >$grub_cfg
        set timeout=5
        menuentry "reinstall" {
            insmod all_video
            search --no-floppy --label --set=root os
            linux /vmlinuz inst.stage2=hd:LABEL=installer:/install.img inst.ks=$ks $extra_cmdline $console_cmdline
            initrd /initrd.img
        }
EOF
    fi

    cat "$grub_cfg"
}

trans() {
    info "start trans"

    mod_motd

    # 先检查 modloop 是否正常
    # 防止格式化硬盘后，缺少 ext4 模块导致 mount 失败
    # https://github.com/bin456789/reinstall/issues/136
    ensure_service_started modloop

    cat /proc/cmdline
    clear_previous
    add_community_repo

    # 需要在重新分区之前，找到主硬盘
    # 重新运行脚本时，可指定 xda
    # xda=sda ash trans.start
    if [ -z "$xda" ]; then
        find_xda
    fi

    if [ "$distro" != "alpine" ]; then
        setup_web_if_enough_ram
        # util-linux 包含 lsblk
        # util-linux 可自动探测 mount 格式
        apk add util-linux
    fi

    # dd qemu 切换成云镜像模式，暂时没用到
    # shellcheck disable=SC2154
    if [ "$distro" = "dd" ] && [ "$img_type" = "qemu" ]; then
        # 移到 reinstall.sh ?
        distro=any
        cloud_image=1
    fi

    if is_use_cloud_image; then
        case "$img_type" in
        qemu)
            create_part
            download_qcow
            case "$distro" in
            centos | almalinux | rocky | oracle | redhat | anolis | opencloudos | openeuler)
                # 这几个系统云镜像系统盘是8~9g xfs，而我们的目标是能在5g硬盘上运行，因此改成复制系统文件
                install_qcow_by_copy
                ;;
            ubuntu)
                # 24.04 云镜像有 boot 分区（在系统分区之前），因此不直接 dd 云镜像
                install_qcow_by_copy
                ;;
            *)
                # debian fedora opensuse arch gentoo any
                dd_qcow
                resize_after_install_cloud_image
                modify_os_on_disk linux
                ;;
            esac
            ;;
        raw)
            # 暂时没用到 raw 格式的云镜像
            dd_raw_with_extract
            resize_after_install_cloud_image
            modify_os_on_disk linux
            ;;
        esac
    elif [ "$distro" = "dd" ]; then
        case "$img_type" in
        raw)
            dd_raw_with_extract
            if false; then
                # linux 扩容后无法轻易缩小，例如 xfs
                # windows 扩容在 windows 下完成
                resize_after_install_cloud_image
            fi
            modify_os_on_disk windows
            ;;
        qemu) # dd qemu 不可能到这里，因为上面已处理
            ;;
        esac
    else
        # 安装模式
        case "$distro" in
        alpine)
            install_alpine
            ;;
        arch | gentoo | aosc)
            create_part
            install_arch_gentoo_aosc
            ;;
        nixos)
            create_part
            install_nixos
            ;;
        fnos)
            create_part
            install_fnos
            ;;
        *)
            create_part
            mount_part_for_iso_installer
            case "$distro" in
            centos | almalinux | rocky | fedora | ubuntu | redhat) install_redhat_ubuntu ;;
            windows) install_windows ;;
            esac
            ;;
        esac
    fi

    # 需要用到 lsblk efibootmgr ，只要 1M 左右容量
    # 因此 alpine 不单独处理
    if is_efi; then
        del_invalid_efi_entry
        add_default_efi_to_nvram
    fi

    info 'done'
    # 让 web 输出全部内容
    sleep 5
}

# 脚本入口
# debian initrd 会寻找 main
# 并调用本文件的 create_ifupdown_config 方法
: main

# 复制脚本
# 用于打印错误或者再次运行
# 路径相同则不用复制
# 重点：要在删除脚本之前复制
if ! [ "$(readlink -f "$0")" = /trans.sh ]; then
    cp -f "$0" /trans.sh
fi
trap 'trap_err $LINENO $?' ERR

# 删除本脚本，不然会被复制到新系统
rm -f /etc/local.d/trans.start
rm -f /etc/runlevels/default/local

# 提取变量
extract_env_from_cmdline

# 带参数运行部分
# 重新下载并 exec 运行新脚本
if [ "$1" = "update" ]; then
    info 'update script'
    # shellcheck disable=SC2154
    wget -O /trans.sh "$confhome/trans.sh"
    chmod +x /trans.sh
    exec /trans.sh
elif [ "$1" = "alpine" ]; then
    info 'switch to alpine'
    distro=alpine
    # 后面的步骤很多都会用到这个，例如分区布局
    cloud_image=0
elif [ -n "$1" ]; then
    error_and_exit "unknown option $1"
fi

# 无参数运行部分
# 允许 ramdisk 使用所有内存，默认是 50%
mount / -o remount,size=100%

# 同步时间
# 1. 可以防止访问 https 出错
# 2. 可以防止 https://github.com/bin456789/reinstall/issues/223
#    E: Release file for http://security.ubuntu.com/ubuntu/dists/noble-security/InRelease is not valid yet (invalid for another 5h 37min 18s).
#    Updates for this repository will not be applied.
# 3. 不能直接读取 rtc，因为默认情况 windows rtc 是本地时间，linux rtc 是 utc 时间
# 4. 允许同步失败，因为不是关键步骤
sync_time || true

# 安装 ssh 并更改端口
apk add openssh
if is_need_change_ssh_port; then
    change_ssh_port / $ssh_port
fi

# 设置密码，添加开机启动 + 开启 ssh 服务
if is_need_set_ssh_keys; then
    set_ssh_keys_and_del_password /
    printf '\n' | setup-sshd
else
    change_root_password /
    printf '\nyes' | setup-sshd
fi

# 设置 frpc
# 并防止重复运行
if [ -s /configs/frpc.toml ] && ! pidof frpc >/dev/null; then
    info 'run frpc'
    add_community_repo
    apk add frp
    while true; do
        frpc -c /configs/frpc.toml || true
        sleep 5
    done &
fi

# shellcheck disable=SC2154
if [ "$hold" = 1 ]; then
    if is_run_from_locald; then
        info "hold"
        exit
    fi
fi

# 正式运行重装
# shellcheck disable=SC2046,SC2194
case 1 in
1)
    # ChatGPT 说这种性能最高
    exec > >(exec tee $(get_ttys /dev/) /reinstall.log) 2>&1
    trans
    ;;
2)
    exec > >(tee $(get_ttys /dev/) /reinstall.log) 2>&1
    trans
    ;;
3)
    trans 2>&1 | tee $(get_ttys /dev/) /reinstall.log
    ;;
esac

if [ "$hold" = 2 ]; then
    info "hold 2"
    exit
fi

# swapoff -a
# umount ?
sync
reboot
