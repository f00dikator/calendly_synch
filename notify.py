# -*- coding: utf-8 -*-
# Version: 1.0.0

__author__ = 'John Lampe'
__email__ = 'dmitry.chan@gmail.com'


import yaml
import logging
import os
import argparse
import pytz
import pdb
from logging.handlers import TimedRotatingFileHandler
import calendly
import smtplib
from time import sleep
import base64
import datetime
import re
import time
#from datetime import datetime


def main(myclient):
    """
    Main entry point into code
    :param myclient: Calendly client object
    :return: None
    """

    try:
        timezone_shift = config['calendly']['timezone'] * 3600
        logging.info("Timezone shift of {} seconds".format(timezone_shift))
    except:
        logging.error("No timezone entry in yaml. Using 0 (e.g. GMT)")
        timezone_shift = 0.0

    known_messages = []
    #read the known messages from text file
    try:
        hashes = open(config['hashes']['file'], "r")
        my_line = hashes.readline()
        while my_line:
            val = my_line.strip('\n')
            known_messages.append(val)
            my_line = hashes.readline()
    except Exception as e:
        logging.error("Failed to open {}. Error: {}".format(config['hashes']['file'], e))

    hashes.close()
    not_done = True
    while not_done:
        if datetime.datetime.today().isoweekday() > 5:
            logging.info("Weekend. Skipping")
            sleep(3600 * 12)
            continue

        #2022-01-22T00:00:00Z
        current_utc_time = str(datetime.datetime.utcnow())
        time_hash = current_utc_time.split(' ')
        current_utc_time = "{}T05:00:00Z".format(time_hash[0])
        try:
            http_response = myclient.get_events(current_utc_time)['collection']
        except Exception as e:
            logging.error("Failed to get events. Error: {}".format(e))
            http_response = []

        for response in http_response:
            try:
                response_uri = response['uri']
                invited_uri = "{}/invitees".format(response_uri)
            except Exception as e:
                logging.error("Failed to retrieve the uri field from {}. Error: {}".format(response, e))
                continue

            try:
                event_details = myclient.get_event_details(response_uri).json()['resource']
                invitee_details = myclient.get_event_details(invited_uri).json()['collection']
                invitees = ["{} - {}".format(x['name'], x['email']) for x in invitee_details]
            except Exception as e:
                logging.error("Failed to retrieve details of event {}. Error: {}".format(response_uri, e))
                continue

            current_epoch_time = time.time()
            meeting_name = ''
            epoch_time = 0.0

            try:
                start_time = event_details['start_time']
                my_time = convert_utc_to_local(start_time)
                epoch_time = convert_utc_to_epoch(start_time)
                meeting_name = event_details['name']
            except Exception as e:
                logging.error("Failed to convert time. Error: {}".format(e))
                continue


            if epoch_time > current_epoch_time:
                time_diff = (epoch_time + timezone_shift) - current_epoch_time
                try:
                    current_message = "From: {}\nTo: {}\nSubject: calendly appts\n\n{} {} {}".format\
                        (config['smtp']['sender_email'], config['smtp']['text_recip'],
                        my_time, meeting_name, invitees)
                    current_message_encoded = current_message.encode('ascii')
                    current_message_encoded = base64.b64encode(current_message_encoded)
                    current_message_encoded = current_message_encoded.decode('ascii')

                    if (current_message_encoded not in known_messages) or ((time_diff < 1800.0) and time_diff > 0):
                        send_email(current_message)
                        if current_message_encoded not in known_messages:
                            known_messages.append(current_message_encoded)
                            try:
                                hashes = open(config['hashes']['file'], "a")
                                hashes.write("{}\n".format(current_message_encoded))
                                hashes.close()
                            except Exception as e:
                                logging.error("Failed to write new hash to file. Error: {}".format(e))
                    else:
                        logging.info("Duplicate message. Not sending")
                except Exception as e:
                    logging.error("Error printing out time and invitees. Error: {}".format(e))

        logging.info("Sleeping for 5 minutes")
        sleep(300)




def send_email(my_msg):
    """
    sends a text to the configured recipient
    :param my_msg: string message
    :return: None
    """

    try:
        smtp_server = config['smtp']['smtp_server']
        smtp_port = config['smtp']['smtp_port']
        my_email = config['smtp']['sender_email']
        app_passwd = config['smtp']['app_passwd']
        email_recip = config['smtp']['text_recip']
    except Exception as e:
        logging.error("Failed to define SMTP params within config file. Exiting. Error: {}".format(e))
        exit(0)

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(my_email, app_passwd)
    except Exception as e:
        logging.error("Failed to connect to smtp gateway. Error: {}".format(e))
        exit(0)

    try:
        server.sendmail(my_email, email_recip, my_msg)
        logging.info("Message {} sent".format(my_msg))
    except Exception as e:
        logging.error("Failed to send message. Error: {}".format(e))

    server.close()


def convert_utc_to_local(time_utc):
    """
    Convert a UTC date-time string into local time
    :param time_utc: UTC string
    :return: local time or None
    """
    tz = pytz.timezone("America/New_York")
    try:
        converted_time = datetime.datetime.strptime(time_utc, '%Y-%m-%dT%H:%M:%S.000000Z').replace(tzinfo=pytz.utc).astimezone(tz)
        #converted_time = time_utc.replace(tzinfo=pytz.utc).astimezone(tz)
        return converted_time
    except Exception as e:
        logging.error("Failed to convert time {}. Error: {}".format(time_utc, e))
        return None

def convert_utc_to_epoch(timestamp):
    """
    converts utc string timestamp to epoch float
    :param timestamp: string UTC timestamp
    :return: float epoch timestamp
    """
    ret = 0.0
    #2021-12-27T18:00:00.000000Z
    t_reg = re.compile(r'([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})T([0-9]{1,2}):([0-9]{1,2}):')
    results = re.search(t_reg, timestamp, flags=0)
    if results:
        year = int(results.group(1))
        month = int(results.group(2))
        dayt = int(results.group(3))
        hours = int(results.group(4))
        minutes = int(results.group(5))
    else:
        logging.error("Failed to convert UTC time to epoch")
        return ret

    try:
        timestamp = datetime.datetime(year, month, dayt, hours, minutes).timestamp()
    except Exception as e:
        logging.error("Failed to convert UTC to epoch. Error: {}".format(e))
        return ret

    return timestamp


def configure_logging(log_path, date_format, log_format,
                      log_file_name, retention, log_level='INFO'):
    """
    Configures logging based on the pathing, log level, and formatting provided
    :param retention: Number of days to retain the log
    :param log_file_name: Name of the log file
    :param log_path: Path where the log file will be written
    :param date_format: Format the date will appear as in the log file
    :param log_format: Format the entire log message will appear as in the log
    file
    :param log_level: INFO by default, DEBUG if -v argument is given during
    execution
    :return:
    """

    log_file = os.path.join(log_path, log_file_name)

    if not os.path.isdir(log_path):
        os.mkdir("{}".format(log_path))

    rotate_handler = TimedRotatingFileHandler(filename=log_file,
                                              when='midnight',
                                              interval=1,
                                              backupCount=retention)
    # Will be appended to the rotated log: 20190525
    rotate_suffix = "%Y%m%d"
    rotate_handler.suffix = rotate_suffix

    # Attach formatter
    rotate_handler.setFormatter(logging.Formatter(fmt=log_format,
                                                  datefmt=date_format))

    # noinspection PyArgumentList
    logging.basicConfig(handlers=[rotate_handler],
                        level=log_level)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Whois info gathering')
    parser.add_argument('-c', action='store', dest='config_path', help='config file', required=True)
    parser.add_argument('-v', action='store_true', dest='verbosity', help='set script verbosity')
    args = parser.parse_args()

    if not os.path.isfile(args.config_path):
        raise RuntimeError('Configuration file provided does not exist')

    with open(args.config_path) as c:
        config = yaml.safe_load(c)

    logging_conf = config['logging']
    if args.verbosity:
        level = "DEBUG"
    else:
        level = "INFO"

    configure_logging(log_path=logging_conf['path'],
                      date_format=logging_conf['date_format'],
                      log_format=logging_conf['log_format'],
                      log_file_name='find_new_domains.log',
                      log_level=level,
                      retention=logging_conf['retention'])


    logging.info('Executing Script: {0}'.format(__file__))

    try:
        calendly_token = config['calendly']['token']
    except:
        logging.error("No token defined in yaml. Exiting")
        exit(0)

    myclient = calendly.CalendlyClient(calendly_token)

    main(myclient)
