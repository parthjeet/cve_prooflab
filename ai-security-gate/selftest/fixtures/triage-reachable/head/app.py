"""Small image helper built on Pillow."""
from PIL import Image, ImageMath

THUMB_SIZE = (128, 128)


def make_thumbnail(src_path, dst_path):
    image = Image.open(src_path)
    thumb = image.resize(THUMB_SIZE)
    thumb.save(dst_path)
    return dst_path


def apply_filter(expression, image):
    """Apply a pixel expression taken from the request to a band of the image."""
    return ImageMath.eval(expression, a=image)
