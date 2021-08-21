
import requests
import sys
import json
import click
import os
import tabulate
import yaml
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

vmanage_host = os.environ.get("vManage_IP")
vmanage_port = os.environ.get("vManage_PORT")
vmanage_username = os.environ.get("vManage_USERNAME")
vmanage_password = os.environ.get("vManage_PASSWORD")

if vmanage_host is None or vmanage_port is None or vmanage_username is None or vmanage_password is None :
    print("CISCO SDWAN details must be set via environment variables before running.")
    print("export vManage_IP=10.10.20.90")
    print("export vManage_PORT=8443")
    print("export vManage_USERNAME=admin")
    print("export vManage_PASSWORD=C1sco12345")
    print("")
    exit()

class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}

        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            if logger is not None:
                logger.error("No vaild JSESSION ID returned\n")
            exit()

    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jssesionid}
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        api = "/dataservice/client/token"
        url = base_url + api
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None

Auth = Authentication()
jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,vmanage_username,vmanage_password)
token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

if token is not None:
    header = {'Content-Type': "application/json", 'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
else:
    header = {'Content-Type': "application/json", 'Cookie': jsessionid}

base_url = "https://%s:%s/dataservice"%(vmanage_host, vmanage_port)

@click.group()
def cli():

    pass

@click.command()
def device_list():

    click.secho("Retrieving the devices.")

    url = base_url + "/device"

    response = requests.get(url=url, headers=header, verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        print("Failed to get list of devices " + str(response.text))
        exit()

    headers = ["Host-Name", "Device Type", "Device ID", "System IP", "Site ID", "Version", "Device Model"]
    table = list()

    for item in items:
        tr = [item['host-name'], item['device-type'], item['uuid'], item['system-ip'], item['site-id'], item['version'], item['device-model']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))

@click.command()
def template_list():

    click.secho("Retrieving the templates available.")

    url = base_url + "/template/device"

    response = requests.get(url=url, headers=header, verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        print("Failed to get list of templates")
        exit()

    headers = ["Host Name", "Device IP", "Site ID", "Host ID", "Host Type"]
    table = list()

    for item in items:
        tr = [item['host-name'], item['deviceIP'], item['site-id'], item['uuid'], item['personality']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))

@click.command()
@click.option("--template", help="Name of the template to deploy")
@click.option("--variables", help="Device Template variable values yaml file")

def attach(template, variables):

    click.secho("Attempting to attach template.")

    with open(variables) as f:
        config = yaml.safe_load(f.read())

    system_ip = config.get("system_ip")
    host_name = config.get("host_name")
    template_id = template

    template_variables = {
                            "csv-status":"complete",
                            "csv-deviceId": config.get("device_id"),
                            "csv-deviceIP": system_ip,
                            "csv-host-name": host_name,
                            "//system/host-name": host_name,
                            "//system/system-ip": system_ip,
                            "//system/site-id": config.get("site_id"),
                            "/1/vpn_1_if_name/interface/if-name": config.get("vpn_1_if_name"),
                            "/1/vpn_1_if_name/interface/ip/address": config.get("vpn_1_if_ipv4_address"),
                            "/512/vpn-instance/ip/route/0.0.0.0/0/next-hop/vpn_512_next_hop_ip_address/address": config.get("vpn_512_next_hop_ip_address"),
                            "/512/vpn_512_if_name/interface/if-name": config.get("vpn_512_if_name"),
                            "/512/vpn_512_if_name/interface/ip/address": config.get("vpn_512_if_ipv4_address"),
                            "/0/vpn-instance/ip/route/0.0.0.0/0/next-hop/mpls_next_hop/address": config.get("mpls_next_hop"),
                            "/0/vpn-instance/ip/route/0.0.0.0/0/next-hop/public_internet_next_hop/address": config.get("public_internet_next_hop"),
                            "/0/vpn_public_internet_interface/interface/if-name": config.get("vpn_public_internet_interface"),
                            "/0/vpn_public_internet_interface/interface/ip/address": config.get("vpn_public_interface_if_ipv4_address"),
                            "/0/vpn_mpls_interface/interface/if-name": config.get("vpn_mpls_interface"),
                            "/0/vpn_mpls_interface/interface/ip/address": config.get("vpn_mpls_if_ipv4_address"),
                            "//system/gps-location/latitude": config.get("latitude"),
                            "//system/gps-location/longitude": config.get("longitude")
                         }

    payload = {
        "deviceTemplateList":[
        {
            "templateId":template_id,
            "device":[ template_variables ],
            "isEdited":"false",
            "isMasterEdited":"false"
        }
        ]
    }

    url = base_url + "/template/device/config/attachfeature"

    response = requests.post(url=url, data=json.dumps(payload), headers=header, verify=False)
    if response.status_code == 200:
        attach_template_pushid = response.json()['id']
        url = base_url + "/device/action/status/%s"%attach_template_pushid
        while(1):
            template_status_res = requests.get(url,headers=header,verify=False)
            if template_status_res.status_code == 200:
                template_push_status = template_status_res.json()
                if template_push_status['summary']['status'] == "done":
                    if 'Success' in template_push_status['summary']['count']:
                        print("Attached Site 3 vEdge Template")
                    elif 'Failure' in template_push_status['summary']['count']:
                        print("Failed to attach Site 3 vEdge Template")
                        exit()
                    break
            else:
                print("\nFetching template push status failed")
                exit()

    else:
        print("Failed to attach Site 3 vEdge Template")
        exit()

@click.command()
@click.option("--target", help="ID of the device to detach")
@click.option("--sysip", help="System IP of the system to detach")

def detach(target, sysip):

    click.secho("Attempting to detach template.")

    payload = {
        "deviceType":"vedge",
        "devices":[
            {
                "deviceId":str(target),
                "deviceIP":str(sysip)
            }
        ]

    }

    url = base_url + "/template/config/device/mode/cli"

    response = requests.post(url=url, data=json.dumps(payload), headers=header, verify=False)
    if response.status_code == 200:
        id = response.json()["id"]
        url = base_url + "/device/action/status/" + str(id)
        while(1):
            status_res = requests.get(url,headers=header,verify=False)
            if status_res.status_code == 200:
                push_status = status_res.json()
                if push_status['summary']['status'] == "done":
                    if 'Success' in push_status['summary']['count']:
                        print("Changed configuration mode to CLI")
                    elif 'Failure' in push_status['summary']['count']:
                        print("Failed to change configuration mode to CLI")
                        exit()
                    break
    else:
        print("Failed to detach template with error " + response.text)
        exit()


cli.add_command(attach)
cli.add_command(detach)
cli.add_command(device_list)
cli.add_command(attached_devices)
cli.add_command(template_list)

if __name__ == "__main__":
    cli()
