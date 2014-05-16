from distutils.core import setup

with open('LICENSE') as file:
    license = file.read()

setup(
    name='stalker',
    version='0.1.0',
    url='https://github.com/elyezer/stalker/',
    author='Elyézer Rezende',
    packages=['stalker'],
    description='Stalker is an application that uses bluetooth to track '
                'position inside buildings',
    license=license,
)
