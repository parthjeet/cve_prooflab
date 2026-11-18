"""Small file-tools module."""
import os
import shutil


def list_dir(path):
    return sorted(os.listdir(path))


def file_size(path):
    return os.path.getsize(path)


def copy_file(src, dst):
    shutil.copyfile(src, dst)
    return dst


def remove_file(path):
    os.remove(path)
