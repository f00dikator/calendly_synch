# -*- coding: utf-8 -*-
# Version: 1.0.0
# Class file for calendly

__author__ = 'John Lampe'
__email__ = 'dmitry.chan@gmail.com'

import requests
import json
import re
import pdb
import logging


class CalendlyClient:
    def __init__(self, token, verify=True):
        """
        Main entry-point into class
        :param token: A valid Calendly API Token
        :param verify: defaults to True for verify TLS/SSL certs
        """
        self.base_url = "https://api.calendly.com/"
        self.session = requests.Session()
        self.session.verify = verify
        self.uuid = None
        if not token:
            logging.error("No token was presented. Exiting")
            exit(0)

        self.session.headers = {"Content-Type": "application/json", "Accept": "application/json",
                                "Authorization": "Bearer {}".format(token)}

        #retrieve our UUID
        data = self.get_users()

        if not data:
            logging.error("Failed to retrieve user information. Exiting")
            exit(0)
        else:
            logging.info("Retrieved user information. Retrieving UUID")
            #uri': 'https://api.calendly.com/users/0627a314-3b49-48f6-a32b-52b65dd32fda'}}
            try:
                uri = data['resource']['uri']
                uri_regex = re.compile(r'https:.*\/users\/([0-9a-f\-]+)')
                result = re.search(uri_regex, uri, flags=0)
                if result:
                    self.uuid = result.group(1)
                    logging.info("Using UUID of {}".format(self.uuid))
                else:
                    logging.error("Failed to parse out the UUID. Exiting")
                    exit(0)
            except Exception as e:
                logging.error("Failed to retrieve uri field. Error: {}".format(e))

    def get(self, endpoint, **kwargs):
        """
        Generic function to send an HTTP GET request
        :param endpoint: the part of the URI after the 'base'
        :param kwargs: Any additional args to be passed to GET command
        :return: dict
        """
        if not endpoint:
            logging.error('No domain provided for GET Request')
            return {}

        try:
            request_url = "{}/{}".format(self.base_url, endpoint)
            get_params = kwargs.get('params')
            if get_params:
                logging.info("Issuing GET {} with params set to {}".format(request_url, get_params))
                http_response = self.session.get(request_url,
                                                 params=get_params)
            else:
                http_response = self.session.get(request_url, **kwargs)
                logging.info("Issuing GET {}".format(request_url))

            if http_response and http_response.json():
                return http_response.json()
            else:
                logging.error("Nothing returned for request {}".format(request_url))
                try:
                    logging.error("Error message {}".format(http_response.json()))
                except Exception as e:
                    logging.error("No error message was returned. Error: {}".format(e))

                return {}
        except Exception as e:
            logging.error("Failed to send GET request {} : {}".format(request_url, e))
            return {}

    def get_users(self, uuid=None):
        """
        Retrieve the users
        :param uuid: string, User UUID
        :return: dict
        """
        # /users/{uuid} or "me" to define caller
        ret = {}
        if not self.uuid and not uuid:
            logging.info("No UUID specified. Using default of 'me'")
            uuid = "me"
        elif uuid and not self.uuid:
            # uuid is known and passed, so go ahead and update self.uuid
            self.uuid = uuid
        elif self.uuid and not uuid:
            uuid = self.uuid

        req = "users/{}".format(uuid)
        try:
            ret = self.get(req)
        except Exception as e:
            logging.error("Failed to get '{}'. Error: {}".format(req, e))

        return ret

    def get_events(self, timestamp):
        """
        Get the collection of events that occur after the UTC timestamp
        :param timestamp: string UTC timestamp
        :return: dict
        """
        # List All Events
        ret = {}
        #req = "scheduled_events?user={}users/{}".format(self.base_url, self.uuid)
        #2020-01-02T12:30:00Z
        req = "scheduled_events?min_start_time={}&user={}users/{}".format(timestamp,
                                                                self.base_url, self.uuid)

        try:
            ret = self.get(req)
            #pdb.set_trace()
        except Exception as e:
            logging.error("Failed to get events. Error: {}".format(e))

        return ret

    def get_event_details(self, uri):
        """
        Get the details of an event
        :param uri: string, The URI of the event
        :return: HTTP return object
        """
        # event details on one specific URI
        ret = {}
        try:
            http_response = self.session.get(uri)
        except Exception as e:
            logging.error("Failed to get event details. Error: {}".format(e))
            http_response = None

        if http_response:
            return http_response
        else:
            return ret

