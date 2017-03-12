Rule Parsing
============

The **idstools** rule parsing can parse individual rule strings as
well as multiple rules from a file or file like objects.

The Rule Object
---------------

The parsing functions will return one, or a list of Rule objects that
present the rule as a dictionary.

.. autoclass:: idstools.rule.Rule
   :noindex:

.. note:: Parsed rules are primarily read only, with the exception of
          toggling the enabled state of the rule, modification is not
          really supported.

Parsing
-------
	  
.. automethod:: idstools.rule.parse   
   :noindex:

.. automethod:: idstools.rule.parse_fileobj   
   :noindex:

.. automethod:: idstools.rule.parse_file
   :noindex:      

Printing
--------

The string representation of the object will print the full rule
respecting the enabled option of the rule.

For example::

  >>> idstools.rule.parse('alert ip any any -> any any (msg:"TEST MESSAGE"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)')
  >>> rule = idstools.rule.parse('alert ip any any -> any any (msg:"TEST MESSAGE"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)')
  >>> print(rule)
  alert ip any any -> any any (msg:"TEST MESSAGE"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)
  >>> rule["enabled"] = False
  >>> print(rule)
  # alert ip any any -> any any (msg:"TEST MESSAGE"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)
  
A brief description of the rule can be printed with
:meth:`idstools.rule.Rule.brief` or a string representing the rule ID
can be printed with :meth:`idstools.rule.Rule.idstr`.

Flowbit Resolution
------------------

The :class:`idstools.rule.FlowbitResolver` is able to resolve the
flowbits for a set of rules presented as a dictionary.

