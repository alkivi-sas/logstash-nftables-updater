#!/usr/bin/env python
# -*-coding:utf-8 -*
"""
Update nftables set for alkivi_connections that are allowed to connect to logstash
"""
import logging
import click
import nftables
import json
import socket
import ipaddress

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


def get_nftables():
    global NFT
    if NFT is not None:
        return NFT
    nft = nftables.Nftables()
    nft.set_json_output(True)
    NFT = nft
    return nft


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
    try:
        data = socket.gethostbyname(domain)
        try:
            ipaddress.ip_address(data)
            return data
        except ValueError:
            logger.warning(f"Domain {domain} resolv to ip {data} but is not valid")
            return None
    except Exception as e:
        logger.warning(f"Unable to resolve {domain}", e)
        return None


def add_ip(ip):
    command = f"add element inet firewall alkivi_connections {{{ip}}}"
    return run_nft_command(command)


def remove_ip(ip):
    command = f"delete element inet firewall alkivi_connections {{{ip}}}"
    return run_nft_command(command)


@click.group()
@click.option("--debug", default=False, is_flag=True, help="Toggle Debug mode")
@click.option("--dry/--no-dry", default=True, is_flag=True, help="Toggle DRY mode")
@click.pass_context
def run(ctx: click.Context, debug: bool, dry: bool):
    """General group."""
    if debug:
        logger.set_min_level_to_print(logging.DEBUG)
        logger.set_min_level_to_save(logging.DEBUG)
        logger.set_min_level_to_mail(None)
        logger.debug("debug activated")

    if dry:
        logger.set_min_level_to_save(logging.DEBUG)
        logger.info("DRY MODE activated")
    else:
        logger.set_min_level_to_mail(logging.WARNING)

    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    ctx.obj["dry"] = dry


@run.command()
@click.pass_context
def update(ctx):
    """Will update nftables set alkivi_connections with current_ips."""
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

    if "elem" not in set_data:
        logger.warning("Unable to extract elem from set_data", set_data)
        exit(1)
    current_ips = set(set_data["elem"])
    logger.debug("current_ips are", current_ips)

    # Build new_ips
    new_ips = set()
    with open("/etc/alkivi.conf.d/alkivi_connections.conf", encoding="utf-8") as f:
        for line in f:
            line = line.replace("\n", "").strip()
            if line:
                ip = get_domain_ip(line)
                if ip is not None:
                    new_ips.add(ip)
    logger.debug("Current IPs are", new_ips)

    for ip in current_ips:
        if ip not in new_ips:
            logger.debug(f"Will remove ip {ip}")
            result = remove_ip(ip)
            if result is None:
                logger.warning(f"Unable to remove ip {ip}")
            else:
                logger.info(f"Successfully removed ip {ip}")

    for ip in new_ips:
        if ip not in current_ips:
            logger.debug(f"Will add ip {ip}")
            result = add_ip(ip)
            if result is None:
                logger.warning(f"Unable to add ip {ip}")
            else:
                logger.info(f"Successfully added ip {ip}")


if __name__ == "__main__":
    try:
        run()
    except Exception as exception:
        logger.exception(exception)
