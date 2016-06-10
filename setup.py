import codecs
import os
import re
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

# Some general-purpose code stolen from
# https://github.com/jeffknupp/sandman/blob/5c4b7074e8ba5a60b00659760e222c57ad24ef91/setup.py

here = os.path.abspath(os.path.dirname(__file__))


class Tox(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import tox
        errcode = tox.cmdline(self.test_args)
        sys.exit(errcode)


def read(*parts):
    # intentionally *not* adding an encoding option to open
    return codecs.open(os.path.join(here, *parts), 'r').read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
    name='seccs',
    version=find_version('seccs', '__init__.py'),

    description='Secure Content Store',
    long_description=open('README.rst').read(),

    url='https://github.com/netleibi/seccs',

    author='Dominik Leibenger',
    author_email='python-seccs@mails.dominik-leibenger.de',

    license='Apache Software License',

    classifiers=[
            'Development Status :: 2 - Pre-Alpha',

            'Intended Audience :: Developers',
            'Topic :: Software Development :: Libraries :: Python Modules',

            'License :: OSI Approved :: Apache Software License',

            'Operating System :: OS Independent',

            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 3'
    ],

    packages=['seccs'],

    install_requires=['fastchunking'],

    test_suite='seccs.test',
    tests_require=['tox', 'pycrypto>=2.7a1'],
    cmdclass={'test': Tox}
)
