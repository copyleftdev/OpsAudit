import paramiko
import re
import time



def collect_ips(fname):
    """ Parses a given text file and get all IP's , returns a list of IP's """
    server_ips = []

    with open(fname,'r') as inputf:
        for each_line in inputf.readlines():
            ip_regex = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', each_line)
            if len(ip_regex) <=0:
                pass
            else:
                server_ips.append(ip_regex)

    return server_ips


def ops_audit(host,port,uname,password):
    """ A simple test to check a list of servers for the utiliztion of legacy ops password """
    paramiko.util.log_to_file('logs/ops_audit_ssh.log')
    s = paramiko.SSHClient()
    s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        s.connect(host,port,uname,password)
        with open('logs/ops_audit_fails.log','w+') as auditlog:
            auditlog.write("{} allowed legacy ops authentication.".format(host))
    except paramiko.ssh_exception.AuthenticationException:
        pass
    s.close()


def server_shell(host, port, uname, password,command):
    """Invoke shell on linux box, return  results"""
    resp = ""
    paramiko.util.log_to_file('logs/process_collect.log')
    s = paramiko.SSHClient()
    s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    s.connect(host, port, uname, password)

    shell = s.invoke_shell()
    shell.send(command)
    time.sleep(2)
    shell.send("\n")
    resp += shell.recv(9999)
    print resp

server_shell("targeta0.codetestcode.io",22,'root','OMITT','ls -al')
