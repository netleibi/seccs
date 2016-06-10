"""Simple reference counter implementations."""
import abc


class BaseReferenceCounter(object):

    """Abstract base class for reference counters."""
    __metaclass__ = abc.ABCMeta

    def inc(self, key):
        """Abstract increment interface.

        Args:
            key: Key whose reference counter shall be incremented.

        Returns:
            Number of references of key after increment.
        """
        raise NotImplementedError

    def dec(self, key):
        """Abstract decrement interface.

        Args:
            key: Key whose reference counter shall be decremented.

        Returns:
            Number of references of key after decrement.
        """
        raise NotImplementedError


class NoReferenceCounter(BaseReferenceCounter):

    """Non-counting reference counter, always returns 1 for any key.

    Can be used to disable reference counting where a reference counter is
    required.
    """

    def inc(self, key):
        """Increment interface.

        Returns:
            1
        """
        return 1

    def dec(self, key):
        """Decrement interface.

        Returns:
            1
        """
        return 1


class DatabaseReferenceCounter(BaseReferenceCounter):

    """Database-backed reference counter.

    Uses a given database to store reference counters. The reference counter of
    an element `key` is stored as follows:
    
        * If its value is 0, `key` is not stored in the database.
        * If its value is > 0, its int value is stored in the database under
          `key`.

    Args:
        database: Database object with a dict-like interface, i.e., implementing
            the operations __getitem__, __setitem__ and __delitem__.
    """

    def __init__(self, database):
        super(DatabaseReferenceCounter, self).__init__()

        self._database = database

    def inc(self, key):
        """Incrementes reference counter of key.

        See :meth:`.BaseReferenceCounter.inc`.
        """
        database = self._database
        database[key] = new_count = (
            database[key] if key in database else 0) + 1
        return new_count

    def dec(self, key):
        """Decrementes reference counter of key.

        See :meth:`.BaseReferenceCounter.dec`.
        """
        database = self._database
        new_count = database[key] - 1
        if new_count == 0:
            del database[key]
        else:
            database[key] = new_count
        return new_count


class KeySuffixDatabaseReferenceCounter(DatabaseReferenceCounter):

    """Database-backed reference counter.

    Similar to :class:`.DatabaseReferenceCounter`, but the reference counter of
    a `key` is not stored directly under `key`, but under `key` || `suffix`.

    Args:
        database: Database object with a dict-like interface, i.e., implementing
            the operations __getitem__, __setitem__ and __delitem__.
        suffix: Suffix for keys.
    """

    def __init__(self, database, suffix):
        super(KeySuffixDatabaseReferenceCounter, self).__init__(database)

        self._suffix = suffix

    def inc(self, key):
        """Incrementes reference counter of key.

        See :meth:`.DatabaseReferenceCounter.inc`.
        """
        return DatabaseReferenceCounter.inc(self, key + self._suffix)

    def dec(self, key):
        """Decrementes reference counter of key.

        See :meth:`.DatabaseReferenceCounter.dec`.
        """
        return DatabaseReferenceCounter.dec(self, key + self._suffix)
