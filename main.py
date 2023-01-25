#!/usr/bin/python3
# CLI Utiliti to parse Jasmin Logs and generate a report
# Usage: jasmin-report [OPTIONS] COMMAND [ARGS]...
#
# Options:
#   --debug / --no-debug  Enable verbose output
#   --help                Show this message and exit.
#
# Commands:
#   print  Generate SMS Usage Report
#
# Usage: jasmin-report print [OPTIONS]
#
#   Generate SMS Usage Report
#
# Options:
#   --incoming    Boolean : Generate incoming messages report only
#   --outgoing    Boolean : Generate outgoing messages report only
#   --cid TEXT    Limit report to specifid provider. E.g: ALMADAR, LIBYANA, etc
#   --uid TEXT    Limit report to specifid user. E.g: WHMCS, ZLITEN, etc
#   --year TEXT   Limit report to specifid year. E.g: 2021
#   --month TEXT  Limit report to specifid month. E.g: 02
#   --help        Show this message and exit.
#
# Developed by Ahmed Shibani
# Version: 1.0.0

import click
import os
import re
from rich.console import Console
from rich.table import Table as RTable
from datetime import datetime
from peewee import *
from rich.progress import track

LOGS_PATH = "./logs/jasmin/"

db = SqliteDatabase("my_database.db")

console = Console()


class BaseModel(Model):
    class Meta:
        database = db


class File(BaseModel):
    name = CharField(unique=True)
    created = DateTimeField(default=datetime.now)
    processed = BooleanField(default=False)


class CID(BaseModel):
    name = CharField(unique=True)


class UID(BaseModel):
    name = CharField(unique=True)


class HTTPAPILog(BaseModel):
    date = DateField()
    time = TimeField()
    cid = ForeignKeyField(CID, field="name")
    uid = ForeignKeyField(UID, field="name")
    to = CharField(unique=False)
    msgid = CharField(unique=True)
    created = DateTimeField(default=datetime.now)


class MessageLog(BaseModel):
    date = DateField()
    time = TimeField()
    cid = ForeignKeyField(CID, field="name")
    fr = CharField(unique=False)
    msgid = CharField(unique=True)
    created = DateTimeField(default=datetime.now)


def http_api_log_parser(data):
    # Date Extractor
    try:
        date_expr = r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
        date_str = re.search(date_expr, data).group(0)
        # date = datetime.strptime(date_str, "%Y-%m-%d")
        date = date_str
    except:
        date = ""

    # Time extractor
    try:
        time_expr = r"\d{2}:\d{2}:\d{2}"
        time = re.search(time_expr, data).group(0)
    except:
        time = ""

    # UID Extractor
    try:
        uid_expression = r"\[uid:(\w+)\]"
        uid = re.search(uid_expression, data).group(1)
    except:
        uid = ""

    # CID Extractor
    try:
        cid_expressions = r"\[cid:(\w+)\]"
        cid = re.search(cid_expressions, data).group(1)
    except:
        cid = ""

    # msgid Extractor
    try:
        msgid_expr = r"\[msgid:([a-z0-9\-]+)\]"
        msgid = re.search(msgid_expr, data).group(1)
    except:
        msgid = ""

    # to Extractor
    try:
        to_expr = r"\[to:(\d+)\]"
        to = re.search(to_expr, data).group(1)
    except:
        to = ""

    log_line = {
        "date": date,
        "time": time,
        # "direction": direction,
        "uid": uid.upper(),
        "cid": cid.upper(),
        "to": to,
        "msgid": msgid,
    }
    return log_line


def messages_log_parser(data):
    # Date Extractor
    try:
        date_expr = r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
        date_str = re.search(date_expr, data).group(0)
        # date = datetime.strptime(date_str, "%Y-%m-%d")
        date = date_str
    except:
        date = ""

    # Time extractor
    try:
        time_expr = r"\d{2}:\d{2}:\d{2}"
        time = re.search(time_expr, data).group(0)
    except:
        time = ""

    # CID Extractor
    try:
        cid_expressions = r"\[cid:(\w+)\]"
        cid = re.search(cid_expressions, data).group(1)
    except:
        cid = ""

    # msgid Extractor
    try:
        msgid_expr = r"\[queue-msgid:([a-z0-9\-]+)\]"
        msgid = re.search(msgid_expr, data).group(1)
    except:
        msgid = ""

    # From Extractor
    try:
        fr_expr = r"\[from:(\d+)\]"
        fr = re.search(fr_expr, data).group(1)
    except:
        fr = ""

    log_line = {
        "date": date,
        "time": time,
        # "direction": direction,
        "cid": cid.upper(),
        "fr": fr,
        "msgid": msgid,
    }
    return log_line


def http_api_summary(data):
    # Build CID unique set
    cids = set([item["cid"] for item in data if item["cid"] != ""])
    # Build UDI unique set
    uids = set([item["uid"] for item in data if item["uid"] != ""])

    for cid in cids:
        CID.get_or_create(name=cid)
    for uid in uids:
        UID.get_or_create(name=uid)

    with db.atomic():
        for data_dict in data:
            try:
                if not data_dict["msgid"] == "":
                    HTTPAPILog.create(**data_dict)
            except IntegrityError:
                if DEBUG:
                    print_error(
                        "Unable to insert due to unique constraint: %s" % data_dict
                    )


def messages_summary(data):
    # Build CID unique set
    cids = set([item["cid"] for item in data if item["cid"] != ""])

    for cid in cids:
        CID.get_or_create(name=cid)

    with db.atomic():
        for data_dict in data:
            try:
                if not data_dict["msgid"] == "":
                    MessageLog.create(**data_dict)
            except IntegrityError:
                if DEBUG:
                    print_error(
                        "Unable to insert due to unique constraint: %s" % data_dict
                    )


def process_http_api():
    log_file_slugs = os.listdir(LOGS_PATH)
    log_file_slugs = [x for x in log_file_slugs if x.startswith("http-api")]
    # print_info("Processing HTTP API Logs... Please wait")
    for i in track(
        log_file_slugs,
        description="Processing HTTP API Logs... Please wait",
    ):
        if not File.get_or_none(name=i) or i[-3:] == "log":
            if DEBUG:
                print_success("Processing file %s" % i)
            with open(LOGS_PATH + i, "r") as fp:
                http_api = []
                lines = fp.readlines()
                for line in lines:
                    http_api.append(http_api_log_parser(line))
                http_api_summary(http_api)
                if DEBUG:
                    print_success("Processed %s entries from %s" % (len(http_api), i))
                File.get_or_create(name=i, processed=True)
        else:
            if DEBUG:
                console.log("%s is already processed" % i)


def process_messages():
    log_file_slugs = os.listdir(LOGS_PATH)
    log_file_slugs = [x for x in log_file_slugs if x.startswith("messages")]
    # print_info("Processing Message Logs... Please wait")
    for i in track(
        log_file_slugs, description="Processing Message Logs... Please wait"
    ):
        if not File.get_or_none(name=i) or i[-3:] == "log":
            if DEBUG:
                print_success("Processing file %s" % i)
            with open(LOGS_PATH + i, "r") as fp:
                messages = []
                lines = fp.readlines()
                for line in lines:
                    if "SMS-MO" in line:
                        messages.append(messages_log_parser(line))
                messages_summary(messages)
                if DEBUG:
                    print_success("Processed %s entries from %s" % (len(messages), i))
                File.get_or_create(name=i, processed=True)
        else:
            if DEBUG:
                console.log("%s is already processed" % i)


def generate_api_report():
    # console.log("Generating report")
    table = RTable(show_header=True, header_style="bold blue")
    table.add_column("Month", width=12)
    table.add_column("User", justify="center")
    table.add_column("Provider", justify="center")
    table.add_column("SMS Count", justify="center")

    # Months-Year Set
    q = HTTPAPILog.select(HTTPAPILog.date).order_by(HTTPAPILog.date)

    date_set = list(
        dict.fromkeys(str(i.date.year) + "-" + str(i.date.strftime("%m")) for i in q)
    )

    if OYEAR:
        date_set = [i for i in date_set if i.startswith(OYEAR)]

    if OMONTH:
        date_set = [i for i in date_set if "-" + OMONTH in i]

    if OUID:
        uids_set = [OUID.upper()]
    else:
        uids_q = UID.select()
        uids_set = set(i.name for i in uids_q)

    cids_q = CID.select()
    cids_set = set(i.name for i in cids_q)

    for date in track(date_set, description="Generating Outgoing Messages table"):
        for uid in uids_set:
            query = (
                CID.select(CID, fn.Count(HTTPAPILog.id).alias("count"))
                .join(HTTPAPILog, JOIN.LEFT_OUTER)
                .where(HTTPAPILog.date.startswith(date))
                .where(HTTPAPILog.uid == uid)
                .group_by(CID)
            )
            for i in query:
                if OCID:
                    if i.name == OCID.upper():
                        table.add_row(date, uid, i.name, str(i.count))
                else:
                    table.add_row(date, uid, i.name, str(i.count))
            # table.add_row(end_section=True)

    # click.echo("\nOutgoing SMS Messages Report")
    # click.echo("----------------------------")
    return table


def generate_messages_report():
    table = RTable(show_header=True, header_style="bold blue")
    table.add_column("Month", width=12)
    table.add_column("Provider", justify="center")
    table.add_column("SMS Count", justify="center")

    # Months-Year Set
    q = MessageLog.select(MessageLog.date).order_by(MessageLog.date)

    date_set = list(
        dict.fromkeys(str(i.date.year) + "-" + str(i.date.strftime("%m")) for i in q)
    )

    if OYEAR:
        date_set = [i for i in date_set if i.startswith(OYEAR)]

    if OMONTH:
        date_set = [i for i in date_set if "-" + OMONTH in i]
    if OCID:
        cids_set = [OCID.upper()]
    else:
        cids_q = CID.select()
        cids_set = set(i.name for i in cids_q)
    for date in track(date_set, description="Generating Incoming Messages table"):
        for cid in cids_set:
            query = (
                CID.select(CID, fn.Count(MessageLog.id).alias("count"))
                .join(MessageLog, JOIN.LEFT_OUTER)
                .where(MessageLog.date.startswith(date))
                .where(MessageLog.cid == cid)
            )
            for i in query:
                table.add_row(date, cid, str(i.count))
            # table.add_row(end_section=True)

    # click.echo("\nIncoming SMS Messages Report")
    # click.echo("----------------------------")
    return table


@click.group()
@click.option("--debug/--no-debug", default=False, help="Enable verbose output")
def main(debug):
    console.log("Jasmin Summary Report... Starting")
    global DEBUG

    DEBUG = debug
    if debug:
        print_info("Debug mode is %s" % ("on"))

    File.create_table()
    HTTPAPILog.create_table()
    CID.create_table()
    UID.create_table()
    MessageLog.create_table()


@main.command(help="Generate SMS Usage Report")
@click.option(
    "--incoming",
    help="Boolean : Generate incoming messages report only",
    default=False,
    is_flag=True,
)
@click.option(
    "--outgoing",
    help="Boolean : Generate outgoing messages report only",
    default=False,
    is_flag=True,
)
@click.option(
    "--cid", help="Limit report to specifid provider. E.g: ALMADAR, LIBYANA, etc"
)
@click.option("--uid", help="Limit report to specifid user. E.g: WHMCS, ZLITEN, etc")
@click.option("--year", help="Limit report to specifid year. E.g: 2021")
@click.option("--month", help="Limit report to specifid month. E.g: 02")
def print(incoming, outgoing, cid, uid, year, month):
    # Main command
    global OCID
    global OUID
    global OYEAR
    global OMONTH
    OCID = cid
    OUID = uid
    OYEAR = year
    OMONTH = month
    if not incoming:
        process_http_api()
        api_report = generate_api_report()

    if not outgoing:
        process_messages()
        messages_report = generate_messages_report()

    if not incoming:
        console.print("\nOutgoing Messages Report", style="bold")
        console.print(api_report)

    if not outgoing:
        console.print("\nIncoming Messages Report", style="bold")
        console.print(messages_report)


# Helper pretty print functions
def print_info(s):
    click.echo(click.style("[!] " + s, fg="yellow"))


def print_error(s):
    click.echo(click.style("[x] " + s, fg="red"))


def print_success(s):
    click.echo(click.style("[+] " + s, fg="green"))


if __name__ == "__main__":
    main()
