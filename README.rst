==================================
seccs --- the SECure Content Store
==================================

.. image:: https://travis-ci.org/netleibi/seccs.svg?branch=master
    :target: https://travis-ci.org/netleibi/seccs

.. image:: https://badge.fury.io/py/seccs.svg
    :target: https://badge.fury.io/py/seccs

.. image:: https://readthedocs.org/projects/seccs/badge/?version=latest
    :target: http://seccs.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

What it is
----------

`seccs` is a Python library that realizes a secure and efficient hash-table-like
data structure for contents on top of any existing key-value store as provided
by, e.g., cloud storage providers.

It has been developed as part of the work [LS17]_ at CISPA, Saarland University.

Installation
------------

::

   $ pip install seccs

If you want to use AES-SIV encryption (you probably want!), you also need to install PyCrypto 2.7a1 which is not yet available in PyPI::

	$ pip install https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.7a1.tar.gz

Usage and Overview
------------------

`seccs` is a Python implementation of `sec-cs`, a secure and efficient
hash-table-like data structure for contents. It stores its data on top of any
existing database providing a key-value store interface. Thus, it is likewise
usable with in-memory :code:`dict` objects, persistent databases like
:code:`ZODB`, and many cloud storage providers.

Its details are described in [LS17]_. In short, it is suitable for usage on
`untrusted` cloud storage and has the following desirable properties:

    * Confidentiality:
        Stored contents are securely encrypted using a symmetric key.
    * Authenticity:
        `sec-cs` guarantees authenticity of all stored contents,
        irrespective of gurantees of the underlying database.
    * Storage Efficiency:
        Data deduplication strategies are applied to all stored contents. When
        storing new contents, overlapping parts of existing contents are
        automatically reused as to avoid redundancy.
        `sec-cs` is optimized for efficiency in presence of `many` similar
        contents: Storage costs of an n-bytes content that differs only slightly
        from an existing content are in O(log n).

Typical Use Case
^^^^^^^^^^^^^^^^

In the most-typical configuration, `sec-cs` chunks its contents hierarchically
using ML-CDC (see [LS17]_), usually relying on Rabin Karp hashes, and stores the
resulting nodes in a `database` after applying AES-SIV-256 for encryption and
authentication. From a user perspective, we have to initialize a suitable
database object and a 32-bytes key first.

Database and key setup:
   >>> database = dict()
   >>> import os
   >>> key = os.urandom(32)

Note that we might want to store the database and the key at some persistent
location in practice.

Next, we need to create a `crypto wrapper` which is in charge of all the
cryptographic operations. Depending on our security goals (e.g., whether
encryption is required), we could choose any suitable wrapper from
:code:`seccs.crypto_wrapper`. Afterwards, we can instantiate the data structure.

Choice of `crypto wrapper` and instantiation of data structure:
   >>> import seccs
   >>> crypto_wrapper = seccs.crypto_wrapper.AES_SIV_256(key)  # install PyCrypto>=2.7a1 to use AES-SIV
   >>> seccs = seccs.SecCSLite(256, database, crypto_wrapper)  # 256 is the chunk size

.. note::

   Internally, `sec-cs` splits contents into chunks, creates a tree of chunks
   for each of them and inserts each node separately into the `database`. The
   first parameter specifies the desired `average` size of nodes inserted into
   the database. As deduplication is performed at the chunk level, large chunk
   sizes decrease deduplication performance, but they also create less storage
   overhead when storing non-deduplicable contents as fewer nodes have to be
   stored.
   
   Performance is discussed in detail in [LS17]_. If high redundancy is
   expected, 256 bytes is typically a good compromise; otherwise, larger chunk
   sizes might be more suitable.

We can now insert contents...
   >>> content = b"This is a test content."
   >>> digest = seccs.put_content(content)
   >>> repr(digest)
   '\x08,f+\xa74\xdc\x0f\xe5Oo\xcb;\x83\xb9T\x00\x00\x00\x00\x00\x00\x00\x17'

...retrieve them...
   >>> seccs.get_content(digest)
   This is a test content.

...and delete them as soon as they are not needed anymore:
   >>> seccs.delete_content(digest)

Storage Efficiency
^^^^^^^^^^^^^^^^^^

`seccs` avoids redundancy in the `database` wherever possible, as gets clear
in the following example.

Consider this function for measuring the `database`'s current storage costs in bytes:
   >>> import sys
   >>> def dbsize(db):
   >>>     return sum([sys.getsizeof(k) + sys.getsizeof(v) for (k, v) in db.items()])

Initially, the database is empty:
   >>> dbsize(database)
   0

Insertion of a 1 MiB content clearly causes some storage costs:
   >>> content1 = os.urandom(1024*1024)
   >>> digest1 = seccs.put_content(content1)
   >>> dbsize(database)
   1583030

But inserting the same content for a second time does not incur additional costs:
   >>> content2 = content1
   >>> digest2 = seccs.put_content(content2)
   >>> digest1 == digest2  # identical contents yield identical digests
   True
   >>> dbsize(database)
   1583030

Clearly, the database grows if different contents are inserted. However, these
costs are low if inserted contents are similar to existing ones.

Only about 2.3 KiB are required to store another 1 MiB content with one byte changed:
   >>> content3 = b''.join([content1[:512*1024], b'x', content1[512*1024+1:]])
   >>> digest3 = seccs.put_content(content3)
   >>> dbsize(database)
   1585395

Costs are similar even if the identical parts are shifted...
   >>> content4 = b''.join([content1[:512*1024], b'xyz', content1[512*1024+1:]])
   >>> digest4 = seccs.put_content(content4)
   >>> dbsize(database)
   1588010

...and deduplication is also performed if a content consists of parts of different existing contents:
   >>> content5 = b''.join([content1, content3, content4])
   >>> digest5 = seccs.put_content(content5)
   >>> dbsize(database)
   1591009

In the last example, the growth was about 3 KiB.

Furthermore, storage space is reclaimed completely when contents are removed:
   >>> seccs.delete_content(digest5)
   >>> seccs.delete_content(digest4)
   >>> seccs.delete_content(digest3)
   >>> seccs.delete_content(digest2)
   >>> dbsize(database)
   1583030
   >>> seccs.delete_content(digest1)
   >>> dbsize(database)
   0

.. note::

   Every :code:`seccs.delete_content` call undos eactly one
   :code:`seccs.put_content` call. Thus, even if the same content has been
   inserted twice, yielding only a single digest, it has to be deleted twice as
   well to get actually removed.

Testing
-------

`seccs` uses tox for testing, so simply run:

::

   $ tox

References:
    .. [LS17] Dominik Leibenger and Christoph Sorge (2017). sec-cs: Getting the
       Most out of Untrusted Cloud Storage. In Proceedings of the 42nd IEEE
       Conference on Local Computer Networks (LCN 2017), 2017.
       (Preprint: `arXiv:1606.03368 <http://arxiv.org/abs/1606.03368>`_)
