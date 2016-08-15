#!/usr/bin/python3
# -*- coding: utf-8 -*-

from base.plugin.abstract_plugin import AbstractPlugin
from base.model.enum.ContentType import ContentType
from base.util.util import Util


class InstantScan(AbstractPlugin):
    def __init__(self, data, context):
        super(InstantScan, self).__init__()
        self.data = data
        self.context = context
        self.logger = self.get_logger()
        self.script_file_path = '/opt/ahenk/plugins/antivirus/scripts/'
        self.message_code = self.get_message_code()

    def handle_task(self):
        try:
            self.logger.debug('[ ANTIVIRUS ] Antivirus instant scan task is started...')
            result_message = 'Dn : {}'.format(self.Ahenk.dn())
            self.logger.debug('1')
            watchfolder = str(self.data['folderPath'])
            self.logger.debug('2')
            foldersplit = watchfolder.split(";")
            self.logger.debug('[ ANTIVIRUS ] Folder Path/(s) is parsed')
            if Util.is_exist(self.script_file_path):
                for folder in foldersplit:
                    if Util.is_exist(folder):
                        result_code, result, error = self.execute(
                            '{0}downloadscan.sh {1} Instant'.format(self.script_file_path, folder))
                        if result_code > 0:
                            self.logger.debug('[ ANTIVIRUS ] {} directory could not be scanned'.format(folder))
                            result_message += '{} dizini taranamadı\r\n'.format(folder)
                        else:
                            result_message += '{} dizini başarılı bir şekilde tarandı\r\n'.format(folder)
                            self.logger.debug('[ ANTIVIRUS ] {} directory is scanned succesfully'.format(folder))
                    else:
                        result_message += '{} dizini bulunmamakta; bu sebeple taranamadı'
                        self.logger.debug('[ ANTIVIRUS ] {} directory does not exist'.format(folder))
                self.context.create_response(code=self.message_code.TASK_PROCESSED.value,
                                         message=result_message)

            else:
                result_message += 'Tarama işlemlerini gerçekleştiren dizin bulunamadı. Tarama işlemi gerçekleştirilemedi'
                self.logger.debug('[ ANTIVIRUS ] Scanning process could not be started because of unfound scanner controller files')
                self.context.create_response(code=self.message_code.TASK_ERROR.value,
                                         message=result_message)
        except Exception as e:
            self.logger.debug('[ ANTIVIRUS ] Error : {}'.format(str(e)))
            self.context.create_response(code=self.message_code.TASK_ERROR.value,
                                         message='Anlık tarama işlemi yapılırken beklenmedik hata!')



def handle_task(task, context):
    print('Antivirus Plugin Task')
    sample = InstantScan(task, context)
    sample.handle_task()
