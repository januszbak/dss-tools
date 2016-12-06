"""
dss-tools send cli commands to DSS V7 servers

In order to create single exe file run:
C:\Python27>Scripts\pyinstaller.exe --onefile dss-tools.py
And try it:
C:\Python27>dist\dss-tools.exe -h

NOTE:
In case of error: "msvcr100.dll missing ..."
please download and install Microsoft Visual C++ 2010 Redistributable Package (x86) vcredist_x86.exe
"""
from __future__ import print_function
import sys
import time
import logging
import paramiko
import argparse
import collections


__author__ = 'janusz.bak@open-e.com'

MIN_DSS_CLI_API_VERSION = 4


# Script global variables - to be updated in parse_args():
cli_port = 0
new_ip = ''
cli_password = ''
action = ''
delay = 0
nodes = []


def time_stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def print_with_timestamp(msg):
    print('{}  {}'.format(time_stamp(), msg))


def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if 0 <= b <= 255]
        return len(host_bytes) == len(valid) == 4
    except:
        return False


def patch_crypto_be_discovery():
    """
    Monkey patches cryptography's backend detection.
    Objective: support pyinstaller freezing.
    """

    from cryptography.hazmat import backends

    try:
        from cryptography.hazmat.backends.commoncrypto.backend import \
            backend as be_cc
    except ImportError:
        be_cc = None

    try:
        from cryptography.hazmat.backends.openssl.backend import \
            backend as be_ossl
    except ImportError:
        be_ossl = None

    backends._available_backends_list = [
        be for be in (be_cc, be_ossl) if be is not None
    ]


def get_args():

    parser = argparse.ArgumentParser(
        prog='dss-tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''The %(prog)s remotely execute given command.''',
        epilog='''EXAMPLES:
 1. Graceful cluster stop and shutdown using default password and port
      %(prog)s stop-cluster 192.168.0.220 192.168.0.221
 2. Graceful cluster stop and shutdown with non default password and port
      %(prog)s --pswd password --port 22225 stop-cluster 192.168.0.220 192.168.0.221
 3. Start cluster with default password and port
      %(prog)s start-cluster 192.168.0.220 192.168.0.221
 4. Run 100 times in loop graceful cluster stop-shutdown-start test
      %(prog)s stop-start-test 192.168.0.220 192.168.0.221
 5. Shutdown three DSS servers using default port but non default password
      %(prog)s --pswd password shutdown 192.168.0.220 192.168.0.221 192.168.0.222
 6. Reboot single DSS server
      %(prog)s reboot 192.168.0.220
 7. Create vg00
      %(prog)s create-vg00 192.168.0.220
 8. Set IP address on eth1 for nodes 192.168.0.220
      %(prog)s set-ip 192.168.0.220 --new-ip eth1:10.10.10.220
    ''')

    parser.add_argument(
        'cmd',
        metavar='command',
        choices=['stop-cluster', 'start-cluster', 'stop-start-test',
                 'shutdown', 'reboot', 'create-vg00', 'set-ip'],
        help='Available commands:  %(choices)s.'
    )
    parser.add_argument(
        'ip',
        metavar='dss-ip-addr',
        nargs='+',
        help='Enter both cluster nodes IP Addresses if cluster releated '
             'command provided. Enter single or more IP with other commands '
             'accordingly.'
    )
    parser.add_argument(
        '--pswd',
        metavar='password',
        default='admin',
        help='Administrator password, default=admin'
    )
    parser.add_argument(
        '--port',
        metavar='port',
        default=22223,
        type=int,
        help='CLI/API SSH port, default=22223'
    )
    parser.add_argument(
        '--new-ip',
        metavar='eth:ip',
        help='eth#:ip device. Required for "set-ip" command'
    )
    parser.add_argument(
        '--delay',
        metavar='seconds',
        default=30,
        type=int,
        help='User defined reboot/shutdown delay in seconds, default=30'
    )

    # testing argv
    # sys.argv = sys.argv + \
    # ' create-vg00 192.168.0.220 192.168.0.80 192.168.0.81 '.split()
    # testing argv

    args = parser.parse_args()

    global cli_port, new_ip, cli_password, action, delay, nodes

    cli_port = args.port
    new_ip = args.new_ip
    cli_password = args.pswd
    action = args.cmd
    delay = args.delay
    nodes = args.ip

    # validate ip-addr
    for ip in nodes :
        if not valid_ip(ip) :
            print( 'IP address {} is invalid'.format(ip))
            sys.exit(1)

    # detect doubles
    doubles = [ip for ip, c in collections.Counter(nodes).items() if c > 1]
    if doubles:
        print( 'Double IP address: {}'.format(', '.join(doubles)))
        sys.exit(1)

    # validate port
    if not 1024 <= args.port <= 65535:
        print( 'Port {} is out of allowed range 1024..65535'.format(port))
        sys.exit(1)


def send_cli_via_ssh(node_ip_address, command):

    repeat = 100
    counter = 1

    logging.getLogger("paramiko").setLevel(logging.WARNING)

    while True:

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                node_ip_address,
                port=cli_port,
                username='api',
                password= cli_password
            )
            break
        except paramiko.AuthenticationException:
            print_with_timestamp( 'Authentication failed: {}'.format(node_ip_address))
            sys.exit(1)
        except:
            print_with_timestamp( 'Waiting for: {}'.format(node_ip_address))
            counter += 1
            time.sleep(5)

        # Connection timed out
        if counter == repeat:
            print_with_timestamp( 'Connection timed out: {}'.format(node_ip_address))
            sys.exit(1)

    stdin, stdout, stderr = ssh.exec_command(command)
    output_from_node = stdout.read().strip()
    ssh.close()

    return output_from_node


def test_cli_version():
    for node in nodes:
        dss_cli_api_version = int(send_cli_via_ssh(node, 'version').strip())
        if dss_cli_api_version < MIN_DSS_CLI_API_VERSION:
            print( 'CLI/API version 4 or newer is required: {}'.format(node))
            sys.exit(1)


def display_delay(msg):
    for sec in range(delay, 0, -1) :
        print( '{} in {:>2} seconds \r'.format(msg,sec))
        time.sleep(1)


def shutdown_nodes():
    display_delay('Shutdown')
    for node in nodes:
        send_cli_via_ssh(node, 'shutdown')
        print_with_timestamp( 'Shutdown: {}'.format(node))


def reboot_nodes() :
    display_delay('Reboot')
    for node in nodes:
        send_cli_via_ssh(node, 'reboot')
        print_with_timestamp( 'Reboot: {}'.format(node))


def create_volume_group() :
    """
    Returns False if vg cannot be created.
    Returns True is vg was created or was existing already.
    """
    volume_group_present = False
    for node in nodes:
        volume_group_status = \
            send_cli_via_ssh(node, 'volume_group_status').strip()
        if volume_group_status:
            print( 'Volume group on {} already exist: {}'.format(
                node,
                ' '.join([line.split(';')[0] for line in
                          volume_group_status.split()])
            ))
            volume_group_present = True
        else:
            print_with_timestamp( 'Creating vg00 on: {}'.format(node))
            send_cli_via_ssh(node, 'unit_manager create S001 vg00')
            volume_group_status = \
                send_cli_via_ssh(node, 'volume_group_status').strip()
            if volume_group_status:
                print_with_timestamp( 'Created vg00 on: {}'.format(node))
                volume_group_present = True
            else :
                print_with_timestamp( 'Cannot create vg00 on: [}'.format(node))
                volume_group_present = False
    return volume_group_present


def print_nic_settings(node):
    nic_details = send_cli_via_ssh(node, 'get_nicslist --verbose').strip()
    print( '\nNIC details:\n{}'.format(nic_details))


def set_ip():

    node = nodes[0]  # only single IP from command-line will be processed
    done = False

    current_nic_details = send_cli_via_ssh(node, 'get_nicslist').strip()
    current_nic_ip_list = [
        line.split(';')[0::4] for line in current_nic_details.split()
    ]

    if len(new_ip.split(':')) == 2:
        given_nic, given_ip = new_ip.split(':')
    else:
        print( 'Wrong argument {}'.format(new_ip))
        sys.exit(1)

    for nic, ip in current_nic_ip_list :

        if nic != given_nic:
            continue

        if ip == node and nic == given_nic:  # want to change SSH accessed NIC
            print( 'Cannot change NIC-setting used for CLI access: {}:{}'.format(
                given_nic, given_ip
            ))
            print_nic_settings(node)
            sys.exit(1)

        if ip == given_ip :                   ## same IP , do nothing
            print( 'Given IP {}:{} is the same as current IP'.format(
                given_nic, given_ip
            ))
            print_nic_settings(node)
            sys.exit(1)

        print_with_timestamp( 'Node {}, setting {}:{}'.format(node, given_nic, given_ip))
        # fixed netmask 24 (255.255.255.0):
        send_cli_via_ssh(node, 'set_nic {} {} 24'.format(given_nic, given_ip))
        done = True

    if not done:
        print_with_timestamp( 'Node {}, NIC {} does not exist '.format(node, given_nic))

    print_nic_settings(node)


def wait_for_nodes():

    for node in nodes :
        if 'working' in send_cli_via_ssh(node, 'test'):
            print_with_timestamp( 'Node {} is running.'.format(node))
        else:
            print_with_timestamp( 'Node {} is NOT available.'.format(node))


def start_cluster():

    n = 0

    for node in nodes:

        state = send_cli_via_ssh(node, 'cluster_status --get').strip()
        if state in ('STARTED_RUNNING', 'DEGREDED'):
            print_with_timestamp('Cluster was started allready.')
            return
        time.sleep(1)
        print('\nStarting cluster.',end=' ')
        send_cli_via_ssh(node, 'cluster_start --global')
        n = 300
        while n > 0:
            print('.', end = ' ') 
            time.sleep(1)
            n -= 1
            state = send_cli_via_ssh(node, 'cluster_status --get')
            if 'STARTED_RUNNING' in state:
                print()
                print_with_timestamp('Cluster started.\n')
                n = -1
            if 'DEGREDED' in state:
                print()
                print_with_timestamp( 'Cluster started in degreded mode.')
                n = -1
        if n == -1:
            break

    if n != -1:
        print()
        print_with_timestamp( 'Unable to start the cluster.')


def stop_cluster():

    state = ''

    for node in nodes :

        state = send_cli_via_ssh(node, 'cluster_status --get').strip()

        if state in ('STARTED_INACTIVE', 'DISABLED'):
            print_with_timestamp( 'Cluster was stopped already.')
            return

        if state in ('STARTED_RUNNING', 'DEGREDED'):
            print('Cluster is stopping.', end=' ')
            send_cli_via_ssh(node, 'cluster_stop --now')
            n = 120
            while n > 0:
                print('.', end=' ')
                time.sleep(1)
                n -= 1
                state = send_cli_via_ssh(node , 'cluster_status --get')
                if 'DISABLED' in state:
                    n = 0
                    print()
                    print_with_timestamp( 'Cluster stopped.\n')
            if n == 0:
                break

    if 'STARTED_RUNNING' in state:
        print()
        print_with_timestamp('Unable to stop the cluster')


def start_volume_replication_tasks():

    replication_mode_of_volume = {}
    both_secondary_mode_volumes = []

    for node in nodes:
        if 'DISABLED' in send_cli_via_ssh(node,
                                          'cluster_maintenance --status'):
            send_cli_via_ssh(node, 'cluster_maintenance --enable')

        tasks = sorted(send_cli_via_ssh(node, 'task --list').split())
        volumes_details = send_cli_via_ssh(node, 'volume_status').split()

        for task in tasks:
            task_name, task_volume, task_type, task_state = task.split(';')
            task_mode = ''
            for volume_details in volumes_details:

                volume_name, vol_repl_mode = \
                    volume_details.split(';')[0::6]  # [0],[6] => [0::6]
                if volume_name == task_volume:
                    task_mode = vol_repl_mode
                    if 'Secondary' in task_mode:
                        if (
                            replication_mode_of_volume.get(volume_name) ==
                            'Secondary'
                        ):
                            both_secondary_mode_volumes.append(
                                (volume_name, task_name.replace('_reverse', ''))
                            )
                            continue
                        replication_mode_of_volume[volume_name] = 'Secondary'
                        continue

            if (
                'Secondary' in task_mode or
                'starting' in task_state or
                'Off' in task_state
            ):
                continue

            if 'running' in task_state:
                print_with_timestamp( 'Node {}, task {} is running'.format(node, task_name))
                continue

            if 'stopped' in task_state:
                print_with_timestamp( 'Node {}, starting volume replication task: {}'.format(
                    node, task_name
                ))
                send_cli_via_ssh(node,
                                 'task --start {} {}'.format(task_type, task_name))
                n = 60
                while n > 0:
                    print('.', end=' ')
                    time.sleep(1)
                    n -= 1
                    tmp_tasks = send_cli_via_ssh(node, 'task --list').split()
                    for tmp_task in tmp_tasks:
                        if 'running' in tmp_task:
                            print()
                            print_with_timestamp( 'Node {}, task {} started.'.format(
                                node, task_name
                            ))
                            n = 0

    if both_secondary_mode_volumes:
        for vol,task in both_secondary_mode_volumes:
            print_with_timestamp('Volume {}, task {} is set to Secondary mode on both nodes'.format(vol,task))
        print('\nIt is NOT possible to auto-start tasks and cluster. Manual start via GUI is required.')
        print('It is nessesary to check which node was last in service and has most recent data.')
        print('Volumes with most recent data need to be set to "Source" mode.\n')
        sys.exit(1)



def main() :

    get_args()

    wait_for_nodes()
    test_cli_version()

    if action == 'start-cluster':
        start_volume_replication_tasks()
        start_cluster()
    elif  action == 'stop-cluster':
        stop_cluster()
        shutdown_nodes()
    elif action == 'shutdown':
        shutdown_nodes()
    elif action == 'reboot':
        reboot_nodes()
    elif action == 'create-vg00':
        create_volume_group()
    elif action == 'set-ip':
        set_ip()

    if action == 'stop-start-test' :
        for counter in range(1, 101):
            stop_cluster()
            reboot_nodes()
            print( 'Please wait ...')
            time.sleep(60)
            wait_for_nodes()
            start_volume_replication_tasks()
            start_cluster()
            print_with_timestamp('{} PASS\n'.format(counter))


if __name__ == '__main__':

    patch_crypto_be_discovery()

    try:
        main()
    except KeyboardInterrupt:
        print_with_timestamp( 'Interrupted             ')
        sys.exit(0)
