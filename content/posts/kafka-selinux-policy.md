+++
title = "Kafka SELinux Policy"
date = 2019-05-08T10:34:40+02:00
author = "Gabor Tanz"
cover = ""
tags = [ "Apache Kafka", "SELinux", "Security" ]
keywords = ["", ""]
description = ""
showFullContent = false
+++

When confronted with SELinux most people tend to disable it instead of learning about it.
That is also what a lot of people on sites like StackOverflow recommend.
This tends to disabling SELinux from the start even if it might not be a problem.

But disabling SELinux is kind of similar to doing a ```chmod 777``` or running processes as root or with sudo and that is not really something most of us would do.
![setenforce0](/img/dont-disable-selinux.jpg)

So we also initially disabled SELinux when we started to build our Kafka platform.
However eventually it popped up in security reports, which we initially ignored and said we would fix it later (mostly means never).
But one day I said to myself, that I want make that red flag in the report go away and started reading about how to make a SELinux policy.

I was familiar with the concept of SELinux, which really restricts what a application can do on your system, which goes much further than normal directory permissions or ACLs.
But most of the stuff that I have done was setting the correct type labels for applications that already had a policy but didn't use standard config/data paths or enabling/disabling predefined SELinux booleans.
But with the Kafka distribution from Confluent I didn't have any policy and everything was labeled as ```unconfined_u/unconfined_t```.

If you have an application that doesn't interact with other applications you probably could get away with leaving it unconfined while still having SELinux on enforcing.
But that would be, to go back to the previous comparison, like running it as root.
Also, as soon as something from the system wants to interact with it you will get AVC denials as the other application isn't allowed to access unconfined types.
This can be something as trivial as logrotate.

## What is a policy

To write a policy one needs to first understand what a policy is made of.
Basically it is three files, one for defining the type enforcement, one for the file contexts and another optional one for providing an interface that other policies can use when interacting with your defined types

### File contexts

The file context part is defined in a file ```yourpolicy.fc``` which says which directories or files should have which SELinux label.
Example from the apache policy

```c
/etc/apache(2)?(/.*)? gen_context(system_u:object_r:httpd_config_t,s0)
```

If we look at ```man file_contexts``` we can see that the file has the format ```pathname [file_type] context```.
Here the pathname is a regex that includes everything with ```/etc/apache``` or ```/etc/apache2``` in its path.
The file_type is omited, which means every kind of file.
We could restrict it like this:

```
 file_type
                     An optional file type consisting of:
                            -b - Block Device      -c - Character Device
                            -d - Directory         -p - Named Pipe
                            -l - Symbolic Link     -s - Socket
                            -- - Ordinary file
```

Last is the context, which in our case is a macro with the interface ```gen_context(context,mls_sensitivity,[mcs_categories])``` which will just generate the following ```system_u:object_r:httpd_config_t:s0```.
The whole line will instruct selinux to label everything in the defined path with the defined context.


### Type enforcement

The big part of a policy is defined in the file ```yourpolicy.te```. Here you define which types exist and what the permissions on these types are.
Every type that is used in the file context file, that isn't defined elsewhere (is not a standard type) needs to be defined in the type enforcement file.

If you would write a module for the reference policy you wouldn't be allowed to import types from other policies when writing the rules, but rather use the interfaces provided by them.

Example from apache policy:
```c
type httpd_t;
type httpd_exec_t;
init_daemon_domain(httpd_t, httpd_exec_t) 
...

allow httpd_t self:tcp_socket { accept listen };
```

The ```init_daemon_domain``` macro accepts two types allows init/systemd to make a transition to the ```httpd_t``` domain when executing a file with the ```httpd_exec_t``` label, this is your entrypoint.

Further down is a direct enforcement statement without using macros.
This allows processes running in the ```httpd_t``` domain to accept/listen on tcp sockets within the same domain.

### Interfaces

Interfaces are what other policies have to use when interacting with your defined types, the interface is defined in ```yourpolicy.if```.

Example from apache policy:
```c
interface(`apache_signal',`
	gen_require(`
		type httpd_t;
	')

	allow $1 httpd_t:process signal;
')
```
This interface allows other types to send signals to processes running in the ```httpd_t``` domain, it can be used with ```apache_signal(yourdomain_t)```.

## Writing the kafka policy

### Common confluent policy
First we start to categorise all the files provided by the confluent distribution and start to assign them labels in the confluent.fc file.

```c
/opt/confluent(-\d\.\d\.\d)?/bin(/.*)           system_u:object_r:confluent_exec_t:s0
/opt/confluent(-\d\.\d\.\d)?/etc(/.*)           system_u:object_r:confluent_config_t:s0
/opt/confluent(-\d\.\d\.\d)?/lib(/.*)           system_u:object_r:confluent_lib_t:s0
/opt/confluent(-\d\.\d\.\d)?/lib/systemd/system(/.*)        --  system_u:object_r:confluent_unit_file_t:s0
/opt/confluent(-\d\.\d\.\d)?/share(/.*)         system_u:object_r:confluent_usr_t:s0
/opt/confluent(-\d\.\d\.\d)?/src(/.*)           system_u:object_r:confluent_usr_t:s0
/opt/confluent(-\d\.\d\.\d)?/README         --  system_u:object_r:confluent_usr_t:s0
```

We have now split up the files into the types

- executables will have ```confluent_exec_t```
- config files ```confluent_config_t```
- libraries ```confluent_lib_t```
- systemd unit files not residing in /ect ```confluent_unit_file_t```
- other resources or source code ```confluent_usr_t```

Next we will write the type enforcement file in ```confluent.te```

At first we define the module name and version (starting at 0.0.1)
```c
  policy_module(confluent,0.0.1)
```
Next are the type declarations starting with the domain and exec type
```go
  ########################################
  #
  # Declarations
  #

  type confluent_t;
  type confluent_exec_t;
```
Then we use interfaces provided by the reference policy to define which is the domain type and how the domain can be entered.
```c
  domain_type(confluent_t)
  domain_entry_file(confluent_t, confluent_exec_t)
```
Finally we declare the other file types and use interfaces to say they are file types (or config files).
```go
  type confluent_config_t
  files_config_file(confluent_config_t)

  type confluent_lib_t;
  files_type(confluent_lib_t)

  type confluent_usr_t;
  files_type(confluent_usr_t)

  type confluent_unit_file_t;
  files_type(confluent_unit_file_t)
```
The interface file we skip for now.

### Kafka policy

Now we start to categorise the files that explicitly belong to kafka (others could be restproxy, schemaregistry or kafka connect).
We need to think where the files would be stored.
For the config files we choose ```/etc/kafka``` for the data files ```/var/lib/kafka``` and for the logs ```/var/log/kafka```.

This results in the following kafka.fc file
```c
/etc/systemd/system/kafka.service	--	system_u:object_r:systemd_unit_file_t:s0
/opt/confluent(-\d\.\d\.\d)?/bin/kafka-server-start	--	system_u:object_r:kafka_exec_t:s0
/opt/confluent(-\d\.\d\.\d)?/bin/kafka-server-stop	--      system_u:object_r:kafka_exec_t:s0
/opt/confluent(-\d\.\d\.\d)?/etc/kafka(/.*)?		system_u:object_r:kafka_config_t:s0
/etc/kafka(/.*)?		system_u:object_r:kafka_config_t:s0
/var/lib/kafka(/.*)?		system_u:object_r:kafka_sys_content_t:s0
/var/log/kafka(/.*)?		system_u:object_r:kafka_log_t:s0
```
Now comes the type enforcement file.
We first declare our types and say what the are used for with the interfaces.
```go
policy_module(kafka,0.0.1)

########################################
#
# Declarations
#

type kafka_t;
type kafka_exec_t;
init_daemon_domain(kafka_t, kafka_exec_t);

type kafka_config_t;
files_config_file(kafka_config_t)

type kafka_sys_content_t;
files_type(kafka_sys_content_t)

type kafka_log_t;
logging_log_file(kafka_log_t)

type kafka_tmp_t;
files_tmp_file(kafka_tmp_t)
```
We additionally declared a ```kafka_tmp_t``` type, which is used for temporary files.
By using the ```files_tmp_file()``` interface we make it possible to have files under ```/tmp/``` which have the correct types.
The ```logging_log_file()``` interfaces takes care of the permissions under /var/log.

Next we have the port type.
```go
type kafka_port_t; # 9093
```
Now we can finally start defining the rules of our policy, like file directory or socket permissions.
As we have a java application we need to allow executing of memory.
```go
########################################
#
# kafka local policy
#

allow kafka_t self:fd use;
allow kafka_t self:tcp_socket create_stream_socket_perms;
allow kafka_t self:process execmem;
allow kafka_t kafka_port_t:tcp_socket { name_bind name_connect };

# kafka directories and files
manage_dirs_pattern(kafka_t, kafka_sys_content_t, kafka_sys_content_t)
manage_files_pattern(kafka_t, kafka_sys_content_t, kafka_sys_content_t)

allow kafka_t kafka_config_t:dir list_dir_perms;
read_files_pattern(kafka_t, kafka_config_t, kafka_config_t)
read_lnk_files_pattern(kafka_t, kafka_config_t, kafka_config_t)

manage_dirs_pattern(kafka_t, kafka_log_t, kafka_log_t)
append_files_pattern(kafka_t, kafka_log_t, kafka_log_t)
create_files_pattern(kafka_t, kafka_log_t, kafka_log_t)
write_files_pattern(kafka_t, kafka_log_t, kafka_log_t)
read_files_pattern(kafka_t, kafka_log_t, kafka_log_t)
setattr_files_pattern(kafka_t, kafka_log_t, kafka_log_t)
read_lnk_files_pattern(kafka_t, kafka_log_t, kafka_log_t)
logging_log_filetrans(kafka_t, kafka_log_t, file)

# java hsperf files in /tmp
manage_dirs_pattern(kafka_t, kafka_tmp_t, kafka_tmp_t)
manage_files_pattern(kafka_t, kafka_tmp_t, kafka_tmp_t)
files_tmp_filetrans(kafka_t, kafka_tmp_t, { dir file })
```
The next step is to compile the policy and load it. TODO add compilation instruction.

Now we start kafka and see what kind of violations we get in the audit log (we are still in permissive mode).
With the help of ```ausearch``` and ```audit2allow``` we can generate rules, they aren't always optimal, but give a good direction to what we need to do.
```bash
ausearch -a <logid> | audit2allow -R
```

In our case we find out that we need access to the kerberos config and the kerberos port, read keytabs, bind tcp/udp ports and more stuff.
```go
kerberos_read_config(kafka_t)

can_exec(kafka_t, kafka_exec_t)

kernel_read_network_state(kafka_t)
kernel_read_system_state(kafka_t)

corenet_port(kafka_port_t)

corenet_tcp_bind_generic_node(kafka_t)
corenet_udp_bind_generic_node(kafka_t)

# kerberos
corenet_tcp_connect_kerberos_port(kafka_t)
# zookeeper
corenet_tcp_connect_zookeeper_client_port(kafka_t)
# ldap
corenet_tcp_connect_ldap_port(kafka_t)

corecmd_exec_bin(kafka_t)
corecmd_exec_shell(kafka_t)

dev_read_sysfs(kafka_t)
dev_read_rand(kafka_t)

fs_search_cgroup_dirs(kafka_t)
fs_read_cgroup_files(kafka_t)

auth_read_passwd(kafka_t)

sysnet_dns_name_resolve(kafka_t)
```
Some of the rules are common to all java programs, or the confluent start scripts, these are mostly the corecmd_,fs_,dev and auth_ rules.

## Interface for the confluent types
We also find that we need to access some files that are labeled with confluent types.
But the reference policy forbids importing of "foreign" types, so we need to define an interface on the confluent policy.
