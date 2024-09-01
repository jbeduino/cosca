import logging
import colorlog

def setup_logger(name, indent=0, level=logging.INFO):
    prefix="🔹"*indent
    logger = logging.getLogger(name)
    logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = colorlog.ColoredFormatter(
        f"cosca> %(log_color)s%(asctime)s %(name)s{' '*max(0,12-len(name))} {prefix} %(message)s",
        datefmt="%m-%d %H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'bold_cyan',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    )
    handler.setFormatter(formatter)
    if not logger.hasHandlers():
        logger.addHandler(handler)
    return logger

# def setup_logger(name):
#     logger = logging.getLogger(name)
#     logger.setLevel(logging.DEBUG)
#     handler = logging.StreamHandler()
#     handler.setLevel(logging.DEBUG)
#     formatter = colorlog.ColoredFormatter(
#         "%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#         datefmt=None,
#         reset=True,
#         log_colors={
#             'DEBUG': 'cyan',
#             'INFO': 'bold_cyan',
#             'WARNING': 'yellow',
#             'ERROR': 'red',
#             'CRITICAL': 'bold_red',
#         }
#     )
#     handler.setFormatter(formatter)
#     if not logger.hasHandlers():
#         logger.addHandler(handler)
#     return logger
