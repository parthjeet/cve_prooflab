"""Small image helper built on Pillow."""
from PIL import Image

THUMB_SIZE = (128, 128)


def make_thumbnail(src_path, dst_path):
    image = Image.open(src_path)
    thumb = image.resize(THUMB_SIZE)
    thumb.save(dst_path)
    return dst_path
