#!/usr/bin/python3
""" palo alto defender scan report converter """
import json
import logging

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

if __name__ == "__main__":

    # initialize debug mode and logger
    DEBUG = True
    LOGGER = logger_setup(DEBUG)
