"""Small image helper built on Pillow."""
import logging

from PIL import Image

logger = logging.getLogger(__name__)

THUMB_SIZE = (128, 128)


def make_thumbnail(src_path, dst_path):
    logger.info("creating thumbnail")
    image = Image.open(src_path)
    thumb = image.resize(THUMB_SIZE)
    thumb.save(dst_path)
    return dst_path
