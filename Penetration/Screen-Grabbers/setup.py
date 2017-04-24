from distutils.core import setup
import py2exe

setup(options = {"py2exe": {"bundle_files": 3,"compressed":True}}, windows = [{"script":"windows_screen-grabber.py"}], zipfile = None)
