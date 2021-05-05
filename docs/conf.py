# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'OpenPMIx'
copyright = '2021, The OpenPMIx Community'
author = 'The OpenPMIx Community'

# The full version, including alpha/beta/rc tags
# Read the OpenPMIx version from the VERSION file
with open("../VERSION") as fp:
    pmix_lines = fp.readlines()

pmix_data = dict()
for pmix_line in pmix_lines:
    if '#' in pmix_line:
        pmix_line, _ = pmix_line.split("#")
    pmix_line = pmix_line.strip()

    if '=' not in pmix_line:
        continue

    pmix_key, pmix_val = pmix_line.split("=")
    pmix_data[pmix_key.strip()] = pmix_val.strip()

# Release is a sphinx config variable -- assign it to the computed
# PMIx version number.
series = f"{pmix_data['major']}.{pmix_data['minor']}.x"
release = f"{pmix_data['major']}.{pmix_data['minor']}.{pmix_data['release']}{pmix_data['greek']}"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
import sphinx_rtd_theme
extensions = ['recommonmark', "sphinx_rtd_theme"]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', 'venv', 'py*/**']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']


# -- PMIx-specific options -----------------------------------------------

# This prolog is included in every file.  Put common stuff here.

rst_prolog = f"""
.. |mdash|  unicode:: U+02014 .. Em dash
.. |rarrow| unicode:: U+02192 .. Right arrow

.. |pmix_ver| replace:: {release}
.. |pmix_series| replace:: {series}
"""
