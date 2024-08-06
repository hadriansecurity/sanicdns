import os
import sys
from textwrap import dedent

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'SanicDNS'
copyright = '2024, Jasper Insinger, Geert Custers'
author = 'Jasper Insinger, Geert Custers'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
        "breathe",
        "exhale",
        "sphinx_design"
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

doxygen_output_dir = "../../build/docs/doxygen/xml"
breathe_output_dir = "../../build/docs/breathe"

# Breathe configuration
breathe_default_project = "SanicDNS"
breathe_projects = {
    "SanicDNS": doxygen_output_dir
}

exhale_args = {
        "containmentFolder":     "./api",
        "rootFileName":          "library_root.rst",
        "rootFileTitle":         "Library API",
        "doxygenStripFromPath":  "../../",

        ############################################################################
        # HTML Theme specific configurations.                                      #
        ############################################################################
        # Fix broken Sphinx RTD Theme 'Edit on GitHub' links
        # Search for 'Edit on GitHub' on the FAQ:
        #     http://exhale.readthedocs.io/en/latest/faq.html
        "pageLevelConfigMeta": ":github_url: https://github.com/svenevs/exhale-companion",
        ############################################################################
        # Main library page layout example configuration.                          #
        ############################################################################
        "afterTitleDescription": dedent(u'''
        Welcome to the developer reference to Exhale Companion.  The code being
        documented here is largely meaningless and was only created to test
        various corner cases e.g. nested namespaces and the like.

        .. note::

            The text you are currently reading was fed to ``exhale_args`` using
            the :py:data:`~exhale.configs.afterTitleDescription` key.  Full
            reStructuredText syntax can be used.

        .. tip::

           Sphinx / Exhale support unicode!  You're ``conf.py`` already has
           it's encoding declared as ``# -*- coding: utf-8 -*-`` **by
           default**.  If you want to pass Unicode strings into Exhale, simply
           prefix them with a ``u`` e.g. ``u"👽😱💥"`` (of course you would
           actually do this because you are writing with åçćëñtß or
           non-English 寫作 😉).
    '''),
        "afterHierarchyDescription": dedent('''
        Below the hierarchies comes the full API listing.

        1. The text you are currently reading is provided by
           :py:data:`~exhale.configs.afterHierarchyDescription`.
        2. The Title of the next section *just below this* normally defaults to
           ``Full API``, but the title was changed by providing an argument to
           :py:data:`~exhale.configs.fullApiSubSectionTitle`.
        3. You can control the number of bullet points for each linked item on
           the remainder of the page using
           :py:data:`~exhale.configs.fullToctreeMaxDepth`.
    '''),
        "fullApiSubSectionTitle": "Custom Full API SubSection Title",
        "afterBodySummary": dedent('''
        You read all the way to the bottom?!  This text is specified by giving
        an argument to :py:data:`~exhale.configs.afterBodySummary`.  As the docs
        state, this summary gets put in after a **lot** of information.  It's
        available for you to use if you want it, but from a design perspective
        it's rather unlikely any of your users will even see this text.
    '''),
    ############################################################################
    # Individual page layout example configuration.                            #
    ############################################################################
    # Example of adding contents directives on custom kinds with custom title
    "contentsTitle": "Page Contents",
    "kindsWithContentsDirectives": ["class", "file", "namespace", "struct"],
    # This is a testing site which is why I'm adding this
    "includeTemplateParamOrderList": True,
    ############################################################################
    # useful to see ;)
    "verboseBuild": True
}

# Tell sphinx what the primary language being documented is.
primary_domain = "cpp"

# Tell sphinx what the pygments highlight language should be.
highlight_language = "cpp"

# breathe_projects_source = {
#      "auto" : ( "../../src/", ["worker.h"] )
#      }

# Set the path to Breathe generated files
sys.path.insert(0, os.path.abspath(breathe_output_dir))

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
