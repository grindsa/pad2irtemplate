#!/usr/bin/python3
""" palo alto defender scan report converter """
import argparse
import csv
import datetime
import glob
import json
import logging
import os
import sys
import xlsxwriter


def arg_parse():
    """ collect arguments and command line options """

    parser = argparse.ArgumentParser(description='pad2ir_convert.py')

    parser.add_argument('-a', '--add-report-columns', dest='addcolumns', help='add columns from report file to the report', action="store_true")
    parser.add_argument('-d', '--debug', help='debug mode', action="store_true")
    parser.add_argument('-r', dest='FILE', help='report file in csv format', required=True)
    parser.add_argument('-c', '--cve-directory', dest='CVEDIR', help='directory with CVE details', required=True)
    args = parser.parse_args()

    if args.FILE:
        if os.path.exists(args.FILE):
            csv_file = args.FILE
        else:
            print('File \'{0}\' could not be found. Aborting...'.format(args.FILE))
            sys.exit(0)

    if args.CVEDIR:
        if os.path.isdir(args.CVEDIR):
            cve_dir = args.CVEDIR
        else:
            print('Directory \'{0}\' could not be found. Aborting...'.format(args.CVEDIR))
            sys.exit(0)

    if args.addcolumns:
        addcolumns = args.addcolumns
    else:
        addcolumns = False

    if args.debug:
        debug = args.debug
    else:
        debug = False

    return (debug, csv_file, cve_dir, addcolumns)


def cve_import(logger, cve_dir):
    """ load cve json files """
    logger.debug('cve_import({0})'.format(cve_dir))

    cve_dict = {}
    for file_name in glob.glob("{0}/*.json".format(cve_dir)):
        logger.debug('load {0}'.format(file_name))
        with open(file_name, encoding='utf8') as json_file:
            cve_list = json.load(json_file)
            if 'CVE_Items' in cve_list:
                for cve in cve_list['CVE_Items']:
                    cve_id = cve['cve']['CVE_data_meta']['ID']
                    if cve_id not in cve_dict:
                        cve_dict[cve_id] = cve
    return cve_dict

def logger_setup(debug):
    """ setup log handle """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    logging.basicConfig(
        format='%(asctime)s - pad2ir_convert - %(levelname)s - %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S",
        level=log_mode)
    logger = logging.getLogger('pad2ir_convert')
    return logger

def pad2ir_convert(logger, pad_cve_list):
    """ convert format """
    logger.debug('pad2ir_convert()')

    converted_list = []
    for cve in pad_cve_list:
        cve['CreationDate'] = datetime.datetime.now().strftime("%Y.%m.%d")
        cve['ScanType'] = 'Services and Vulnerabilities Analysis'
        cve['ScannerName'] = 'Palo Alto Defender'
        cve['Target'] = '{0}, {1}, {2}'.format(cve['Hostname'], '10.0.0.1', cve['Repository'])
        cve['Port'] = ''
        cve['Protocol'] = ''
        if cve['CVE ID']:
            cve['Faultline'] = '{0}-{1}'.format(cve['Hostname'], cve['CVE ID'])
        else:
            cve['Faultline'] = '{0}-{1}'.format(cve['Hostname'], 'unk')
        cve['CVE'] = cve['CVE ID']
        # cve['VulnName'] = cve['Description']
        if (cve['CVE ID'] and cve['Packages']):
            cve['VulnName'] = '{0}-{1}'.format(cve['Packages'],cve['CVE ID'])
        else:
            cve['VulnName'] = ''
        cve['CVSS Base score'] = cve['CVSS']
        cve['CVSS Temporal score'] = ''
        cve['3rd Party Vendor Name'] = cve['Packages']
        cve['Recommendation'] = ''
        cve['Supplementary Information'] = ''
        cve['Steps to reproduce the problem'] = ''
        converted_list.append(cve)
    return pad_cve_list

def padreport_enrich(logger, pad_cve_list, cve_dict):
    """ add additional data """
    logger.debug('padreport_enrich()')
    ir_cve_list = []
    for cve in pad_cve_list:
        if cve['CVE ID']:
            if cve['CVE ID'] in cve_dict:
                logger.debug('{0} found. add CVSSv3: {0}'.format(cve['CVE ID'], cve_dict[cve['CVE ID']]['impact']['baseMetricV3']['cvssV3']['vectorString']))
                cve['CVSS Vector'] = cve_dict[cve['CVE ID']]['impact']['baseMetricV3']['cvssV3']['vectorString']
            else:
                logger.debug('{0} not found in cve_dict'.format(cve['CVE ID']))
                cve['CVSS Vector'] = ''
        else:
            cve['CVSS Vector'] = ''
        ir_cve_list.append(cve)
    return ir_cve_list

def padreport_import(logger, csv_file):
    """ load report from palo alto defender """
    logger.debug('padreport_import({0})'.format(csv_file))

    column_list = []
    with open(csv_file, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                # print({", ".join(row)})
                column_list = list(row.keys())
                break
                # line_count += 1

        return (column_list, list(csv_reader))

def xls_dump(logger, column_list, fname, ir_cve_list):
    """ generate excel file """

    workbook = xlsxwriter.Workbook('{0}'.format(fname))
    sheet = workbook.add_worksheet('Report')

    row = 0
    f_tabhead = workbook.add_format({'bold': True, 'bg_color': '#000080', 'font_color': '#ffffff'})
    # column width
    sheet.set_column('A:A', 11)
    sheet.set_column('B:B', 34)
    sheet.set_column('C:C', 18)
    sheet.set_column('D:D', 30)
    sheet.set_column('G:G', 30)
    sheet.set_column('H:H', 15)
    sheet.set_column('I:I', 15)
    sheet.set_column('J:J', 44)
    sheet.set_column('M:M', 10)
    sheet.set_column('O:O', 50)
    sheet.set_column('P:P', 25)
    sheet.set_column('Q:Q', 25)
    sheet.set_column('R:R', 30)
    sheet.set_column('S:S', 5)
    # add column headers
    for idx, ele in enumerate(column_list):
        sheet.write(row, idx, ele, f_tabhead)

    for cve in ir_cve_list:
        row +=1
        for idx, ele in enumerate(column_list):
            if ele:
                sheet.write(row, idx, cve[ele])
            else:
                sheet.write(row, idx, '')

    sheet.freeze_panes(1, 0)
    workbook.close()

if __name__ == "__main__":

    # initialize debug mode and logger
    (DEBUG, PAD_REPORT, CVE_DIR, ADD_REPORT_COLUMNS) = arg_parse()
    LOGGER = logger_setup(DEBUG)

    COLUMN_LIST = ['CreationDate', 'ScanType', 'ScannerName', 'Target', 'Port', 'Protocol', 'Faultline', 'CVE', 'VulnName', 'CVSS Vector', 'CVSS Base score', 'CVSS Temporal score', 'Severity', 'Recommendation', 'Description', '3rd Party Vendor Name', 'Supplementary Information', 'Steps to reproduce the problem']

    cve_dict = cve_import(LOGGER, CVE_DIR)
    # cve_dict = {'foo': 'bar'}
    (pad_column_list, pad_cve_list) = padreport_import(LOGGER, PAD_REPORT)

    # add columns from pad-report to xls
    if ADD_REPORT_COLUMNS:
        COLUMN_LIST.append('')
        COLUMN_LIST.extend(pad_column_list)

    if pad_cve_list and cve_dict:
        # add cvss vector
        pad_cve_list = padreport_enrich(LOGGER, pad_cve_list, cve_dict)
        # convert list
        ir_cve_list = pad2ir_convert(LOGGER, pad_cve_list)

        xls_dump(LOGGER, COLUMN_LIST, '{0}-{1}.xlsx'.format(PAD_REPORT, datetime.datetime.now().strftime("%Y.%m.%d-%H-%M-%S")), ir_cve_list)
