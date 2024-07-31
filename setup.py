from setuptools import setup, find_packages

setup(
    name='javaliCheatSheets',
    version='0.0.1',
    description='Private package to javaliCheatSheets, a tool to retrieve personal cheat sheets',
    url='git@github.com:JavaliMZ/JavaliCheatSheets.git',
    author='Sylvain Júlio',
    author_email='syjulio123@gmail.com',
    license='unlicense',
    packages=find_packages(),  # Automatically finds all packages in the directory
    zip_safe=False,
    install_requires=find_packages(),
    entry_points={
        'console_scripts': [
            'javaliCheatSheets=javaliCheatSheets:main'
        ]
    }
)
