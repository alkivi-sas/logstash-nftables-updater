#!/usr/bin/env python
# -*-coding:utf-8 -*
"""
Update nftables set for alkivi_connections that are allowed to connect to logstash
"""
import logging
import os
import click
import nftables
import json
import ipaddress
import time
import psutil
import signal
import dns.resolver

from jinja2 import Template
from alkivi.logger import Logger

# Define the global logger
logger = Logger(
    min_log_level_to_mail=logging.WARNING,
    min_log_level_to_save=logging.DEBUG,
    min_log_level_to_print=logging.INFO,
    min_log_level_to_syslog=None,
    filename="/var/log/alkivi/nftables-update.py.log",
    emails=["monitoring@alkivi.fr"],
)

NFT = None
CACHE_DOMAIN = {}
RESOLVER = None
SLEEP_INTERVAL = 0.1


def get_resolver():
    global RESOLVER
    if RESOLVER is not None:
        return RESOLVER

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    RESOLVER = resolver
    return resolver


def load_data():
    f = open("/etc/alkivi.conf.d/alkivi_connections.conf", encoding="utf-8")
    return json.load(f)


def get_nftables():
    global NFT
    if NFT is not None:
        return NFT
    nft = nftables.Nftables()
    nft.set_json_output(True)
    NFT = nft
    return nft


def update_logstash_conf(connections_data):
    template_file = "./templates/02-identity.conf.jinja"
    template_string = ""
    with open(template_file, "r") as t:
        template_string = t.read()

    template = Template(template_string)
    description = template.render(connections_data=connections_data)
    with open("/etc/logstash/conf.d/02-identify.conf", "w") as f:
        f.write(description)

    pid = None
    for proc in psutil.process_iter(["pid", "name"]):
        if (
            proc.info["name"] == "java"
            and "/usr/share/logstash/jdk/bin/java" in proc.cmdline()
        ):
            logger.debug(f"Found logstash at PID: {proc.info['pid']} {proc}")
            pid = proc.info["pid"]
            break
    if pid is None:
        logger.warning("Unable to find process in psutil")
    else:
        logger.debug(f"Sending SIGHUP to pid {pid}")
        os.kill(pid, signal.SIGHUP)


def run_nft_command(command):
    nft = get_nftables()
    rc, output, error = nft.cmd(command)
    if error or rc != 0:
        logger.warning(
            f"Unable to run command nft {command} : error is {error}, rc is {rc}"
        )
        return None
    if output:
        logger.debug(f"Output for command {command} is {output}")
        return json.loads(output)
    else:
        return ""


def get_domain_ip(domain):
    global CACHE_DOMAIN
    if domain in CACHE_DOMAIN:
        return CACHE_DOMAIN[domain]

    resolver = get_resolver()
    iteration = 0
    stop = False
    while not stop:
        iteration += 1
        if iteration == 10:
            stop = True

        try:
            answers = resolver.resolve(domain)
            if not len(answers):
                time.sleep(SLEEP_INTERVAL)
                continue
            answer = answers[0]
            if len(answers) > 1:
                logger.warning(
                    f"Got multiple answers for domain {domain} will take the first one"
                )
            ip = answer.to_text()
            try:
                ipaddress.ip_address(ip)
                CACHE_DOMAIN[domain] = ip
                return ip
            except ValueError:
                logger.warning(f"Domain {domain} resolv to ip {ip} but is not valid")
                return None
        except Exception:
            time.sleep(SLEEP_INTERVAL)
            pass

    logger.warning(f"Unable to resolve {domain}")
    exit(0)
    return None


def add_ip(ip):
    command = f"add element inet firewall alkivi_connections {{{ip}}}"
    return run_nft_command(command)


def remove_ip(ip):
    command = f"delete element inet firewall alkivi_connections {{{ip}}}"
    return run_nft_command(command)


@click.group()
@click.option("--debug", default=False, is_flag=True, help="Toggle Debug mode")
@click.option("--force", default=False, is_flag=True, help="Force Update")
@click.pass_context
def run(ctx: click.Context, debug: bool, force: bool):
    """General group."""
    if debug:
        logger.set_min_level_to_print(logging.DEBUG)
        logger.set_min_level_to_save(logging.DEBUG)
        logger.set_min_level_to_mail(None)
        logger.debug("debug activated")

    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    ctx.obj["force"] = debug


@run.command()
@click.pass_context
def update(ctx):
    """Will update nftables set alkivi_connections with current_ips."""
    logger.debug("Starting update")

    force = ctx.obj["force"]

    # List existing IPs
    command = "list set inet firewall alkivi_connections"
    current_data = run_nft_command(command)
    if "nftables" not in current_data:
        logger.warning("Weird json", current_data)
        exit(1)

    current_data = current_data["nftables"]
    if len(current_data) != 2:
        logger.warning("Weird len != 2", current_data)
        exit(1)

    set_data = None
    for element in current_data:
        if "set" in element:
            set_data = element["set"]
            break
    if set_data is None:
        logger.warning("Unable to extract set from data", current_data)
        exit(1)

    current_ips = []
    if "elem" in set_data:
        current_ips = set(set_data["elem"])

    # Build new_ips
    new_ips = set()
    logstash_data = {}
    connections_data = load_data()
    ips_to_customer = {}
    for customer, domains in connections_data.items():
        ips = []
        for domain in domains:
            ip = get_domain_ip(domain)
            if ip is not None:
                new_ips.add(ip)
                ips.append(ip)
        if ips:
            for ip in ips:
                ips_to_customer[ip] = customer
            logstash_data[customer] = ips

    has_change = False
    for ip in current_ips:
        if ip not in new_ips:
            logger.debug(f"Will remove ip {ip}")
            result = remove_ip(ip)
            has_change = True
            if result is None:
                logger.warning(f"Unable to remove ip {ip}")
            else:
                logger.info(f"Successfully removed ip {ip}")

    for ip in new_ips:
        if ip not in current_ips:
            customer = ips_to_customer[ip]
            logger.debug(f"Will add ip {ip} (domain {customer})")
            result = add_ip(ip)
            has_change = True
            if result is None:
                logger.warning(f"Unable to add ip {ip}")
            else:
                logger.info(f"Successfully added ip {ip} for customer {customer}")

    if has_change or force:
        update_logstash_conf(logstash_data)


if __name__ == "__main__":
    try:
        run()
    except Exception as exception:
        logger.exception(exception)
