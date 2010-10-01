import traceback
import paramiko
import binascii
import logging
import socket
import signal
import time
import os


class TimedOutExc(Exception):
    def __init__(self, value = "Timed out"):
        self.__value = value
    def __str__(self):
        return self.__value

def TimedOutFn(f, timeout, *args):
    def handler(signum, frame):
        raise TimedOutExc()

    old = signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        result = f(*args, **kwargs)
    finally:
        signal.signal(signal.SIGALRM, old)
    signal.alarm(0)
    return result

def timed_out(timeout):
    def decorate(f):
        def handler(signum, frame):
            raise TimedOutExc()
        
        def new_f(*args, **kwargs):
            old = signal.signal(signal.SIGALRM, handler)
            signal.alarm(timeout)
            try:
                result = f(*args, **kwargs)
            finally:
                signal.signal(signal.SIGALRM, old)
            signal.alarm(0)
            return result
        
        new_f.func_name = f.func_name
        return new_f

    return decorate

class ConnectionError(Exception):
    def __init__(self, value):
        self.__value = value
    def __str__(self):
        return self.__value

class Connection:
    """
    """
    def __init__(self, hostname, port):
        self.__hostname = hostname
        self.__port = port

    def __del__(self):
	try:
	    self.__t.close()
	except AttributeError:
	    pass	
       
    def setpassword(self, password):
        self.__password = password
 
    def connect(self, username, password=None):
        self.__username = username
        self.__password = password
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((self.__hostname, self.__port))
        except Exception, e:  
            raise ConnectionError(str(e))
        try:
            self.__t = paramiko.Transport(sock)
            try:
                self.__t.start_client()
            except paramiko.SSHException:
                raise ConnectionError('SSH negotiation failed for %s' % self.__hostname)
            try:
                keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            except IOError:
                try:
                    keys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
                except IOError:
                    keys = {}

            self.__agent_auth()
            if not self.__t.is_authenticated():
                self.__t.close()
                raise ConnectionError('authentiation failed on %s' % self.__hostname)        
        except Exception, e:
            raise ConnectionError('caught exception: ' + str(e.__class__) + ': ' + str(e))
            traceback.print_exc()
            try:
                self.__t.close()
            except:
                pass
            return False
        return True

    def close(self):
        try:
            self.__t.close()
        except AttributeError:
            pass

    def __agent_auth(self):
        """
        Attempt to authenticate to the given transport using any of the private
        keys available from an SSH agent.
        """
        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        if len(agent_keys) == 0:
            return
        for key in agent_keys:
            logging.debug('Trying ssh-agent key %s' % binascii.hexlify(key.get_fingerprint()))
            try:
                self.__t.auth_publickey(self.__username, key)
                logging.debug('Key accepted on %s' % self.__hostname)
                return
            except paramiko.SSHException:
                logging.debug('Key not accepted on %s' % self.__hostname)        
        raise ConnectionError('No suitable key found.')

    @timed_out(15)        
    def sudo_command(self, command, **kw):
        """
        We should have a valid connection. If not raise an exception. 
        Attempt to establish a transport over the channel otherwise. 
        """

        # Check if we have an authenticated session:
        if not self.__t.is_authenticated():
            raise ConnectionError('transport not authenticated on %s' % self.__hostname)
        # Check arguments:
        if kw.has_key('maxtry'):
            maxtry = kw.get('maxtry')
        else:
            maxtry = 3
        if kw.has_key('args'):
            command_string = 'PATH=$PATH:/usr/sbin:/usr/local/bin;sudo -S -p [%%u@sudo] %s %s' % (kw.get('args'), command)
        else:
            command_string = 'PATH=$PATH:/usr/sbin:/usr/local/bin;sudo -S -p [%%u@sudo] %s' % command
        # Open the session:
        chan = self.__t.open_session()
        # Execute the command:
        chan.exec_command(command_string)
        # Wait until we have recv_ready. If not recv_ready, we check for recv_stderr_ready.
        # In case it is available, we read and check to see if it is the password prompt.
        # If so we pass the password.

        stderr = ''
        passcount = 0
        while not chan.recv_ready():
            if passcount == maxtry:
                chan.close()
                raise ConnectionError('bad password on %s' % self.__hostname)
            elif chan.recv_stderr_ready():
                stderr = chan.recv_stderr(1024)
                if stderr.find('%s@sudo' % self.__username) > 0:
                    chan.send('%s\r\n' % self.__password)
                    passcount += 1
                    stderr = ''
                elif stderr.find('not in the sudoers') > 0:
                    raise ConnectionError('%s not in the sudoers file on %s' % 
                                          (self.__username, self.__hostname))
                elif stderr.find('not allowed to execute') > 0:
                    raise ConnectionError('%s is not allowed to execute %s on %s' %
                                          (self.__username, command, self.__hostname))
                else:
		            logging.debug('Received stderr from %s:\r\n%s' % (self.__hostname, stderr))
	        
            elif chan.exit_status_ready():
		        break
            else:
                time.sleep(.1)

        stdout = ''
        while chan.recv_ready() or not chan.exit_status_ready():
            data = chan.recv(1048576)
            logging.debug('Received from %s: \r\n%s' % (self.__hostname, data))
            stdout += data
            time.sleep(.1)

        return stdout, stderr, chan.recv_exit_status()

    @timed_out(15)        
    def exec_command(self, command):
        """
        We should have a valid connection. If not raise an exception. 
        Attempt to establish a transport over the channel otherwise. 
        """
        # Check if we have an authenticated session:
        if not self.__t.is_authenticated():
            raise ConnectionError('transport not authenticated on %s' % self.__hostname)
        # Open the session:
        chan = self.__t.open_session()
        # Execute the command:
        chan.exec_command(command)
        # Wait until we have recv_ready. If not recv_ready, we check for recv_stderr_ready.
        stderr = ''
        while not chan.recv_ready():
            if chan.recv_stderr_ready():
                stderr = chan.recv_stderr(1024)
                logging.debug('Err from %s: \r\n%s' % (self.__hostname, stderr))
                time.sleep(.1)
            elif chan.exit_status_ready():
                break
            else:
                time.sleep(.1)

        stdout = '' 
        while chan.recv_ready() or not chan.recv_exit_status_ready():
            data = chan.recv(1048576)
            logging.debug('Received from %s: \r\n%s' % (self.__hostname, data))
            stdout += data
            time.sleep(.1)

        return stdout, stderr, chan.recv_exit_status()
