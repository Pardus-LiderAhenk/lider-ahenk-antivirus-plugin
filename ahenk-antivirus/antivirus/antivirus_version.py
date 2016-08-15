#!/usr/bin/python3
# -*- coding: utf-8 -*-

from base.plugin.abstract_plugin import AbstractPlugin
from base.model.enum.ContentType import ContentType
import json


class AntivirusVersion(AbstractPlugin):
    def __init__(self, data, context):
        super(AntivirusVersion, self).__init__()
        self.data = data
        self.context = context
        self.logger = self.get_logger()
        self.script_file_path = '/opt/ahenk/plugins/antivirus/scripts/'
        self.message_code = self.get_message_code()

    def handle_task(self):

        # Get clamav version
        try:
            (result_code, p_out, p_err) = self.execute("clamscan -V")
            antivirus_version = str(p_out).strip()
            data = {'antivirusVersion': antivirus_version}
            self.logger.debug('[ ANTIVIRUS ] clamav version: ' + antivirus_version)
            self.context.create_response(code=self.message_code.TASK_PROCESSED.value,
                                         message='Antivirus Versiyonu başarıyla getirildi...', data=json.dumps(data),
                                         content_type=ContentType.APPLICATION_JSON.value)
        except Exception as e:
            self.logger.debug('[ ANTIVIRUS ] Error while reading antivirus version: {}'.format(str(e)))
            self.context.create_response(code=self.message_code.TASK_ERROR.value,
                                         message='Antivirus Versiyonuna ulaşılırken beklenmedik hata...')


def handle_task(task, context):
    print('Antivirus Plugin Task')
    sample = AntivirusVersion(task, context)
    sample.handle_task()