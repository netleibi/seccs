"""sec-cs --- the SECure Content Store.

This module provides an implementation of the secure content store data
structure introduced in [LS16]_.

`sec-cs` allows secure and efficient storage of contents in an existing
key-value database, providing the following features:

    * Confidentiality:
        Stored contents are securely encrypted using a symmetric key.
    * Authenticity:
        `sec-cs` guarantees authenticity of all stored contents,
        irrespective of gurantees of the underlying database.
    * Storage Efficiency:
        Data deduplication strategies are applied to all
        stored contents. When storing new contents, overlapping parts of
        existing contents are automatically reused as to avoid redundancy.
        Storage costs of an n-bytes content that differs only slightly from an
        existing content are in O(log n).
        
Note:
    The only `sec-cs` implementation currently included in this module is called
    :class:`SecCSLite`. While it is likely suitable for many projects and can be
    used as is, it is actually intended as a base class for a much more powerful
    variant, :class:`SecCS`, which makes some slight changes to the internal
    storage structure and will be published in the near future.

References:
    .. [LS16] Dominik Leibenger and Christoph Sorge (2016). sec-cs: Getting the
       Most out of Untrusted Cloud Storage. arXiv preprint.
"""
import collections
from itertools import chain
import itertools
import logging
import math
import struct

import seccs.crypto_wrapper
import seccs.rc

__version__ = '0.0.2'


class UnsupportedChunkSizeError(Exception):
    """Raised when trying to instantiate SecCS with an unsupported chunk size."""
    pass


class SecCSLite(object):

    """Secure Content Store `lite`.

    Basic implementation of the Secure Content Store data structure, supports
    only insertion (put), retrieval (get) and deletion (delete) of contents.

    Args:
        chunk_size (int): Target chunk size, i.e., expected size of all chunks
            stored in the database.
        database: Persistent database used as backend. Can be any object with
            a dict-like interface, i.e., any object implementing the operations
            __getitem__, __setitem__, __delitem__ and __contains__.
        crypto_wrapper (:class:`crypto_wrapper.BaseCryptoWrapper`): Crypto
            wrapper object that specifies cryptographic operations to be applied
            to data stored in the `database`.
        chunking_strategy (Optional[:class:`fastchunking.BaseChunkingStrategy`]):
            Chunking strategy that shall be applied to contents. Defaults to
            Rabin-Karp-based content defined chunking with 48-bytes window size.
        reference_counter (Optional[:class:`seccs.rc.BaseReferenceCounter`]):
            Reference counting strategy. By default, reference counters are
            stored in `database` under keys `key` || `"r"`, where `key` is the key
            whose references are counted.
        **kwargs: Extra keyword arguments that you should NOT use unless you
            really, really know what you are doing, e.g.:

            * length_to_height_fn: Function that resolves content lengths to
              appropriate chunk tree heights. May be used to modify the
              multi-level chunking approach performed by default, e.g., to
              degrade it to single-level chunking or similar.
            * height_to_chunk_size_fn: Function that computes the target chunk
              size for a specific level (height) of a chunk tree. May be used
              to create `imbalanced` chunk trees.

    Raises:
        seccs.UnsupportedChunkSizeError: If the chosen chunk size would create
            superchunk nodes with less than two expected children as efficiency
            guarantees would fail in this case (see [LS16]_).
    """

    def __init__(
            self, chunk_size, database, crypto_wrapper, chunking_strategy=None,
            reference_counter=None, **kwargs):
        self._logger = logging.getLogger(__name__)

        """ initialize reference representations depending on digest size """
        self._digest_size = crypto_wrapper.DIGEST_SIZE
        self._initialize_reference_representations()

        """ require S >= 2R unless an alternate height_to_chunk_size_fn is given """
        if chunk_size < 2 * self._R and 'height_to_chunk_size_fn' not in kwargs:
            raise UnsupportedChunkSizeError((
                'target average chunk size of {S} bytes is too small, must be '
                'at least {req} bytes').format(S=chunk_size, req=2 * self._R))

        """ function that calculates the appropriate number of chunking levels
            for a specific content length """
        self._content_length_to_level = kwargs.get('length_to_height_fn', None)
        if not self._content_length_to_level:
            def length_to_height_fn(size):
                return int(max(math.ceil(math.log(size * 1.0 / chunk_size)
                                         / math.log(chunk_size * 1.0 / self._R)),
                               0)) if size != 0 else 0
            self._content_length_to_level = length_to_height_fn

        """ dict that resolves a chunking level to its corresponding chunk size """
        self._level_to_chunksize = self._LevelToChunkSizeDict(
            chunk_size, self._R, kwargs.get('height_to_chunk_size_fn', None))

        """
        Crypto wrapper.

          Expected interface:
            value, digest <- wrap_value(value, height, is_root)
            value <- unwrap_value(value, digest, length, height, is_root)
        """
        self._crypto_wrapper = crypto_wrapper

        """
        Key-value database.

          Expected interface:
            __setitem__(key, value)
            __delitem__(key)
            value <- __getitem__(key)
            True/False <- __contains__(key)
        """
        self._database = database

        """
        Reference counter.

          Expected interface:
            new_count <- inc(key)
            new_count <- dec(key)
        """
        if reference_counter is None:
            reference_counter = seccs.rc.KeySuffixDatabaseReferenceCounter(
                database, 'r')
        self._reference_counter = reference_counter

        """
        Chunking strategy.

        Needs to be a context-sensitive chunking strategy meeting the Chunking
        interface of the fastchunking package.
        """
        if chunking_strategy is None:
            import fastchunking
            chunking_strategy = fastchunking.RabinKarpCDC(
                48, seed=0)  # FIXME: seed should not be 0
        self._chunking_strategy = chunking_strategy
        self._W = chunking_strategy.window_size

    def _initialize_reference_representations(self):
        """Define how chunk references are represented."""

        # size of subchunk references
        digest_size = self._digest_size
        self._R = digest_size

        # format of content references
        self._content_reference_format = '!{digest_size}sQ'.format(
            digest_size=digest_size)

        # format of subchunk references
        self._subchunk_reference_format = '!{digest_size}s'.format(
            digest_size=digest_size)

    """
    Public interface.
    """

    def put_content(self, m, ignore_rc=False):
        """Insert a content into the data structure.

        Args:
            m (str): The message or content that shall be processed and inserted
                into the data structure.
            ignore_rc (Optional[bool]): If True, increase of reference counter
                for the root node of the generated chunk tree is skipped.
                Defaults to False.

        Returns:
            str: Digest of the content that allows its retrieval using
            :meth:`get_content`.
        """
        return self.put_content_and_check_if_new(m, ignore_rc)[0]

    def put_content_and_check_if_new(self, m, ignore_rc=False):
        """Insert a content into the data structure.

        Like :meth:`put_content`, but return value includes information whether
        the content had been in the data structure before.

        Args:
            m (str): The message or content that shall be processed and inserted
                into the data structure.
            ignore_rc (Optional[bool]): If True, increase of reference counter
                for the root node of the generated chunk tree is skipped.
                Defaults to False.

        Returns:
            tuple: (digest, is_new), where `digest` is the content's digest that
            allows its retrieval using :meth:`get_content`, and `is_new`
            is True if the content has been inserted for the first time and
            False if it had existed before.
        """
        l = len(m)
        h = self._content_length_to_level(l)
        k, is_new = self._put_chunk(m, h, h)
        k = k[0]
        if not ignore_rc:
            self._reference_counter.inc(k)
        return (struct.pack(self._content_reference_format, k, l), is_new)

    def get_content(self, k):
        """Retrieve a content from the data structure.

        Args:
            k (str): The digest under which the content is stored.

        Returns:
            str: The content bytestring.
        """
        k, l = struct.unpack(self._content_reference_format, k)
        h = self._content_length_to_level(l)
        return self._get_chunk(k, h, h, l)

    def delete_content(self, k, ignore_rc=False):
        """Delete a content from the data structure.

        Decreases the content's reference counter and deletes its root chunk
        (possibly including children) if no references are left.

        Args:
            k (str): The digest under which the content is stored.
            ignore_rc (Optional[bool]): If True, decrease of reference counter
                of the root node is skipped and root node (possibly including
                children) is deleted straight away.
        """
        k, l = struct.unpack(self._content_reference_format, k)
        h = self._content_length_to_level(l)
        return self._delete_content(k, h, h, l, ignore_rc)

    """
    Helper functions for storing chunk tree nodes in the backend and retrieving
    them without having to deal with (de)serialization issues.
    """

    def _store_node(self, v, h, root_h):
        """Store chunk tree node in database.

        Args:
            v: Node content (str in case of a leaf chunk, list of child
                references otherwise).
            h (int): Height of chunk tree node.
            root_h (int): Height of chunk tree.

        Returns:
            tuple: ((k, ), is_new), where `k` is the digest or key under which
                the node has been stored, and `is_new` is a flag indicating
                whether the node has just been inserted (True) or existed before
                (False).
        """

        if isinstance(v, list):
            """ serialize superchunk:
                use each key as is (and replace None keys by a sequence of zero
                bytes) and concatenate everything """
            serialized_chunk = ''.join([struct.pack(
                self._subchunk_reference_format,
                subchunk_key) for (subchunk_key,) in v])

        else:
            """ leaf chunks do not need any serialization """
            serialized_chunk = v

        """ compute chunk key using digest function """
        serialized_chunk, k = self._crypto_wrapper.wrap_value(
            serialized_chunk, h, h == root_h)

        """ if the chunk already exists, verify its integrity and return its identifier """
        if k in self._database and self._get_node(k, h, root_h) is not None:
            return ((k, ), False)

        """ if we have a new superchunk, increase reference counters for its children """
        if isinstance(v, list):
            for (chunk_id, ) in v:
                self._reference_counter.inc(chunk_id)

        """ create the chunk and return its identifier """
        self._database[k] = serialized_chunk

        return ((k, ), True)

    def _get_node(self, k, h, root_h, l=-1):
        """Retrieve chunk tree node from database.

        Args:
            k (str): Digest or key of the node.
            h (int): Height of the chunk tree node in its chunk tree.
            root_h (int): Height of the full chunk tree.
            l [Optional(int)]: Size of the node representation, if known.
                Defaults to -1.

        Returns:
            Chunk tree node, i.e., a bytestring in case of a leaf chunk (h = 0),
            and a list of subchunk references in case of a superchunk (h > 0).
        """

        v = self._database[k]

        serialized_chunk = self._crypto_wrapper.unwrap_value(
            v, k, h, h == root_h, l)

        if h > 0:
            """ deserialize superchunk """
            return None if serialized_chunk is None else[
                struct.unpack(
                    self._subchunk_reference_format,
                    serialized_chunk[i: i + self._R])
                for i in range(0, len(serialized_chunk),
                               self._R)]
        else:
            return serialized_chunk

    """
    Functions for realization of operations.
    """

    def _put_chunk(self, m, h, root_h):
        """ Compute subtree of a chunk tree for a specific content part and
        store it in the database.

        Args:
            m (str): Content part (message).
            h (int): Height of the considered content part in its content's
                chunk tree.
            root_h (int): Height of chunk tree of the whole content.

        Returns:
            tuple: ((k, ), is_new), where `k` is the digest or key under which
                the chunk has been stored, and `is_new` is a flag indicating
                whether the chunk has just been inserted (True) or existed
                before (False).
        """
        assert h >= 0
        if __debug__:
            self._logger.debug(
                'Store chunk with length %d bytes (levels: %d)', len(m), h)

        if h == 0:
            """ No chunking required """
            return self._store_node(m, h, root_h)  # return (k), is_new

        else:
            """ Chunking required """
            if __debug__:
                self._logger.debug(
                    'Do chunking with target chunk size: %d', self._level_to_chunksize[h - 1])

            """ Determine chunk boundaries for all levels """

            # first boundary is before the content
            boundaries = [(0, h - 1)]

            # determine subsequent boundaries...
            chunker = self._chunking_strategy.create_multilevel_chunker(
                [self._level_to_chunksize[height] for height in range(0, h)])
            # ...and append them to the boundaries list
            # W-1 zeros are prepended
            boundaries.extend(
                chunker.next_chunk_boundaries_levels(m, self._W - 1))

            # make sure that the last boundary is after the content and is a
            # height (h-1)-boundary
            if boundaries[-1][0] == len(m):
                boundaries.pop()
            boundaries.append((len(m), h - 1))

            """ Build chunk tree and store its nodes """

            # initialize temporary nodes (one for each level)
            nodes_levels = dict([(height, []) for height in range(0, h + 1)])

            # process chunks specified by boundaries
            for ((start_position, _), (end_position, boundary_height)) \
                    in zip(boundaries, boundaries[1:]):
                # place leaf chunk at height 0
                # is guaranteed to be cleared during this loop due to the
                # subsequent inner loop
                nodes_levels[0] = m[start_position:end_position]

                # update superchunks and insert nodes that are already complete
                # (including the leaf chunk)
                for height in range(0, boundary_height + 1):
                    # in order to extend the superchunk, we have to insert its
                    # next subchunk
                    nodes_levels[height + 1].append(self._store_node(nodes_levels[height],
                                                                     height, root_h)[0])
                    # subchunk is complete, so prepare new subchunk
                    nodes_levels[height] = []

            # insert root chunk (return (k), is_new)
            return self._store_node(nodes_levels[h], h, root_h)

    def _get_chunk(self, k, h, root_h, l):
        """ Get content part which is stored under some key in the database.
        If content consists of multiple chunks, put them together.

        Args:
            k (str): Digest or key of the node representing the part of the
                chunk tree that is to be retrieved.
            h (int): Height of the node representing the part of the chunk tree
                that is to be retrieved.
            root_h (int): Height of the chunk tree to which the chunk requested
                here belongs.
            l (int): Length of the content represented by the chunk that is to
                be retrieved.

        Returns:
            Content part.
        """
        chunks = [(k, )]
        for height in range(h, 0, -1):
            chunks = chain.from_iterable([self._get_node(k, height, root_h)
                                          for (k, ) in chunks])
        return ''.join([self._get_node(k, 0, root_h) for (k, ) in chunks])

    def _delete_content(self, k, h, root_h, l, ignore_rc=True):
        """ Remove reference from content's root node and delete its root node
        (possibly including children) if necessary.

        Args:
            k (str): The digest under which the content is stored.
            h (int): Height of node `k` in its chunk tree.
            root_h (int): Height of the chunk tree `k` is part of.
            l (int): Length of the content represented by `k`.
            ignore_rc (Optional[bool]): If True, decrease of reference counter
                of the root node is skipped and root node (possibly including
                children) is deleted straight away.
        """
        if ignore_rc or self._reference_counter.dec(k) == 0:
            return self._delete_chunk(k, h, root_h, l)

    def _delete_chunk(self, k, h, root_h, l=-1):
        """ Delete a chunk and all children whose reference counters drop to
        zero.

        Args:
            k (str): The digest of the chunk tree node that is to be deleted.
            h (int): The height of the chunk tree node `k`.
            root_h (int): The height of the chunk tree `k` is part of.
            l [Optional(int)]: The length of the content part represented by
                `k`. Defaults to -1.
        """
        if h > 0:
            v = self._get_node(k, h, root_h)
            for (k_child, ) in v:
                if self._reference_counter.dec(k_child) == 0:
                    self._delete_chunk(k_child, h - 1, root_h)
        del self._database[k]

    """
    Generic helpers.
    """

    class _LevelToChunkSizeDict(collections.defaultdict):

        """
        Dict that caches the target chunk sizes for different chunk tree heights
        to save some computations.
        """

        def __init__(self, target_chunksize, R, height_to_chunk_size_fn=None):
            collections.defaultdict.__init__(self)
            self._target_chunksize = target_chunksize
            self._R = R

            if not height_to_chunk_size_fn:
                height_to_chunk_size_fn = lambda L: int(
                    self._target_chunksize ** (L + 1) / self._R ** L)
            self._height_to_chunk_size_fn = height_to_chunk_size_fn

        def __missing__(self, L):
            self[L] = chunksize = self._height_to_chunk_size_fn(L)
            return chunksize
