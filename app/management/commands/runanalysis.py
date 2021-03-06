import json
import os
import shutil
import sys
from django.conf import settings
from django.core.management.base import BaseCommand

import requests
import slacker

from app.analysis import r
from app.models import Revision


class Command(BaseCommand):
    help = 'runanalysis HELP.'

    def setup(self):
        self.slack_token = None
        self.output_file = os.path.join(
            os.path.expanduser('~'),
            'runanalysis.out.txt'
        )

        # Read Slack API token from the local store
        api_token_file = os.path.join(
            os.path.expanduser('~'),
            settings.SLACK_API_TOKEN_FILE
        )

        if os.path.exists(api_token_file):
            with open(api_token_file, 'r') as _file:
                self.slack_token = _file.read().strip('\n')
        else:
            print(
                '[WARNING] {0} does not exists. No message will be posted to '
                'Slack'.format(api_token_file)
            )

    def handle(self, *args, **options):
        self.setup()
        status = r.run(fname=self.output_file)
        self.slackpost(status)
        self.teardown()

    def is_cve_updated(self):
        response = requests.get(settings.FFMPEG_SECURITY_SRC_URL)
        if response.json()['sha'] != settings.FFMPEG_SECURITY_FILE_SHA:
            return True
        return False

    def slackpost(self, status):
        if self.slack_token:
            slack = slacker.Slacker(self.slack_token)

            message = {
                'channel': settings.SLACK_CHANNEL['name'],
                'username': settings.SLACK_USERNAME,
                'text': '',
            }

            cve_sync_status = 'In-sync'
            if self.is_cve_updated():
                cve_sync_status = 'Out-of-sync'
                status = 1

            # POST to Slack
            if status == 0 or status == 1:
                # Success or Warning
                response = slack.files.upload(
                    self.output_file,
                    title='Association Results',
                    filename='results.txt',
                    channels=[settings.SLACK_CHANNEL['id']]
                )

                color = 'good'

                if status == 1:
                    color = 'warning'

                fields = list()
                fields.append({
                    'title': 'Outcome',
                    'value': 'Success',
                    'short': True
                })
                fields.append({
                    'title': 'CVE Sync. Status',
                    'value': cve_sync_status,
                    'short': True
                })

                message['attachments'] = json.dumps([{
                    'fallback': 'Attack Surface Nightly Run',
                    'title': 'Attack Surface Nightly Run',
                    'color': color,
                    'fields': fields
                }])

                slack.chat.post_message(**message)
            elif status == 2:
                # Error
                print('[SLACK] Error')
                pass
        else:
            print('Slack API token was not appropirately initialized')

    def teardown(self):
        os.remove(self.output_file)
