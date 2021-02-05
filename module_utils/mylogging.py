import logging

formatter = logging.Formatter(
    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fadcos')
hdlr = logging.FileHandler('/var/tmp/ansible-fadcos.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)
