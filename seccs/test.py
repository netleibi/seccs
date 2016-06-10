"""Unit tests.

Performs tests of the seccs data structure with randomly generated contents.

If run via tox / py.test, a single (random) run is performed.

If run directly, the tests are repeated with all seeds that triggered errors in
the past. Note that this requires an extensive amount of time!
"""

import math
import sys
import os
import unittest

# ensure that we include from the parent path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import seccs


class RCTest(unittest.TestCase):

    def test_base_rc(self):
        class Test(seccs.rc.BaseReferenceCounter):

            def inc(self, *args, **kwargs):
                return super(Test, self).inc(*args, **kwargs)

            def dec(self, *args, **kwargs):
                return super(Test, self).dec(*args, **kwargs)

        rc = Test()
        key = os.urandom(32)
        self.assertRaises(NotImplementedError, rc.inc, key)
        self.assertRaises(NotImplementedError, rc.dec, key)

    def test_no_rc(self):
        rc = seccs.rc.NoReferenceCounter()
        key = os.urandom(32)
        self.assertEqual(rc.inc(key), 1)
        self.assertEqual(rc.dec(key), 1)

    def test_database_rc(self):
        database = dict()

        rc = seccs.rc.DatabaseReferenceCounter(database)

        key = os.urandom(32)

        self.assertNotIn(key, database)
        self.assertEqual(rc.inc(key), 1)
        self.assertIn(key, database)
        self.assertEqual(rc.inc(key), 2)
        self.assertEqual(rc.dec(key), 1)
        self.assertEqual(rc.dec(key), 0)
        self.assertNotIn(key, database)

    def test_key_suffix_database_rc(self):
        database = dict()
        suffix = os.urandom(2)

        rc = seccs.rc.KeySuffixDatabaseReferenceCounter(database, suffix)

        key = os.urandom(32)

        self.assertNotIn(key + suffix, database)
        self.assertEqual(rc.inc(key), 1)
        self.assertNotIn(key, database)
        self.assertIn(key + suffix, database)
        self.assertEqual(rc.inc(key), 2)
        self.assertEqual(rc.dec(key), 1)
        self.assertEqual(rc.dec(key), 0)
        self.assertNotIn(key + suffix, database)


class CryptoWrapperTest(unittest.TestCase):

    def test_base_cw(self):
        class Test(seccs.crypto_wrapper.BaseCryptoWrapper):

            def wrap_value(self, *args, **kwargs):
                return super(Test, self).wrap_value(*args, **kwargs)

            def unwrap_value(self, *args, **kwargs):
                return super(Test, self).unwrap_value(*args, **kwargs)

        cw = Test()
        self.assertRaises(NotImplementedError, cw.wrap_value, '', 0, False)
        self.assertRaises(
            NotImplementedError, cw.unwrap_value, '', '', 0, False)

    def test_SHA_256(self):
        cw = seccs.crypto_wrapper.SHA_256()

        value = os.urandom(100)
        height = 0
        is_root = False

        wrapped_value, digest = cw.wrap_value(value, height, is_root)

        self.assertEqual(value, wrapped_value)

        self.assertEqual(
            value, cw.unwrap_value(wrapped_value, digest, height, is_root))

        self.assertRaises(seccs.crypto_wrapper.IntegrityError, cw.unwrap_value,
                          wrapped_value + 'x', digest, height, is_root)
        self.assertRaises(seccs.crypto_wrapper.IntegrityError, cw.unwrap_value,
                          wrapped_value, digest[:-3] + 'xyz', height, is_root)
        self.assertRaises(seccs.crypto_wrapper.IntegrityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, is_root)
        try:
            cw.unwrap_value(wrapped_value, digest, height, not is_root)
        except seccs.crypto_wrapper.IntegrityError:
            self.fail('crypto_wrapper raises IntegrityError unexpectedly')
        self.assertRaises(seccs.crypto_wrapper.IntegrityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, not is_root)

    def test_HMAC_SHA_256(self):
        key = os.urandom(32)
        cw = seccs.crypto_wrapper.HMAC_SHA_256(key)
        key2 = os.urandom(32)
        cw2 = seccs.crypto_wrapper.HMAC_SHA_256(key2)

        value = os.urandom(100)
        height = 0
        is_root = False

        wrapped_value, digest = cw.wrap_value(value, height, is_root)

        self.assertNotEqual(
            (wrapped_value, digest), cw2.wrap_value(value, height, is_root))

        self.assertEqual(value, wrapped_value)

        self.assertEqual(
            value, cw.unwrap_value(wrapped_value, digest, height, is_root))

        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value + 'x', digest, height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest[:-3] + 'xyz', height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, is_root)
        try:
            cw.unwrap_value(wrapped_value, digest, height, not is_root)
        except seccs.crypto_wrapper.AuthenticityError:
            self.fail('crypto_wrapper raises AuthenticityError unexpectedly')
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, not is_root)

    def test_HMAC_SHA_256_DISTINGUISHED_ROOT(self):
        key = os.urandom(32)
        cw = seccs.crypto_wrapper.HMAC_SHA_256_DISTINGUISHED_ROOT(key)
        key2 = os.urandom(32)
        cw2 = seccs.crypto_wrapper.HMAC_SHA_256_DISTINGUISHED_ROOT(key2)

        value = os.urandom(100)
        height = 0
        is_root = False

        wrapped_value, digest = cw.wrap_value(value, height, is_root)

        self.assertNotEqual(
            (wrapped_value, digest), cw2.wrap_value(value, height, is_root))

        self.assertEqual(value, wrapped_value)

        self.assertEqual(
            value, cw.unwrap_value(wrapped_value, digest, height, is_root))

        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value + 'x', digest, height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest[:-3] + 'xyz', height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height, not is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, not is_root)

    def test_HMAC_SHA_256_DISTINGUISHED_ROOT_WITH_LEAF_PADDING(self):
        key = os.urandom(32)
        cw = seccs.crypto_wrapper.HMAC_SHA_256_DISTINGUISHED_ROOT_WITH_LEAF_PADDING(
            key)
        key2 = os.urandom(32)
        cw2 = seccs.crypto_wrapper.HMAC_SHA_256_DISTINGUISHED_ROOT_WITH_LEAF_PADDING(
            key2)

        value = os.urandom(100)
        height = 0
        is_root = False

        wrapped_value, digest = cw.wrap_value(value, height, is_root)

        self.assertNotEqual(
            (wrapped_value, digest), cw2.wrap_value(value, height, is_root))

        self.assertEqual(value, wrapped_value[:len(value)])
        self.assertNotEqual(len(value), len(wrapped_value))

        self.assertEqual(
            value, cw.unwrap_value(wrapped_value, digest, height, is_root, len(value)))

        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value + 'x', digest, height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest[:-3] + 'xyz', height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height, not is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, not is_root)

    def test_AES_SIV_256(self):
        key = os.urandom(32)
        cw = seccs.crypto_wrapper.AES_SIV_256(key)
        key2 = os.urandom(32)
        cw2 = seccs.crypto_wrapper.AES_SIV_256(key2)

        value = os.urandom(100)
        height = 0
        is_root = False

        wrapped_value, digest = cw.wrap_value(value, height, is_root)

        self.assertNotEqual(
            (wrapped_value, digest), cw2.wrap_value(value, height, is_root))

        self.assertNotEqual(value, wrapped_value)
        self.assertEqual(len(value), len(wrapped_value))

        self.assertEqual(
            value, cw.unwrap_value(wrapped_value, digest, height, is_root))

        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value + 'x', digest, height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest[:-3] + 'xyz', height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, is_root)
        try:
            cw.unwrap_value(wrapped_value, digest, height, not is_root)
        except seccs.crypto_wrapper.AuthenticityError:
            self.fail('crypto_wrapper raises AuthenticityError unexpectedly')
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, not is_root)

        wrapped_value, digest = cw.wrap_value('', height, is_root)
        self.assertEqual(
            '', cw.unwrap_value(wrapped_value, digest, height, is_root))

    def test_AES_SIV_256_DISTINGUISHED_ROOT(self):
        key = os.urandom(32)
        cw = seccs.crypto_wrapper.AES_SIV_256_DISTINGUISHED_ROOT(key)
        key2 = os.urandom(32)
        cw2 = seccs.crypto_wrapper.AES_SIV_256_DISTINGUISHED_ROOT(key2)

        value = os.urandom(100)
        height = 0
        is_root = False

        wrapped_value, digest = cw.wrap_value(value, height, is_root)

        self.assertNotEqual(
            (wrapped_value, digest), cw2.wrap_value(value, height, is_root))

        self.assertNotEqual(value, wrapped_value)
        self.assertEqual(len(value), len(wrapped_value))

        self.assertEqual(
            value, cw.unwrap_value(wrapped_value, digest, height, is_root))

        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value + 'x', digest, height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest[:-3] + 'xyz', height, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height, not is_root)
        self.assertRaises(seccs.crypto_wrapper.AuthenticityError, cw.unwrap_value,
                          wrapped_value, digest, height + 1, not is_root)

        wrapped_value, digest = cw.wrap_value('', height, is_root)
        self.assertEqual(
            '', cw.unwrap_value(wrapped_value, digest, height, is_root, 0))


class SecCSLiteTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        import random
        self.seed = kwargs.pop('seed', random.random())
        self.random = random.Random(self.seed)

        self.S = kwargs.pop('S', 128)

        unittest.TestCase.__init__(self, *args, **kwargs)

    def shortDescription(self):
        return 'SecCSLite: S={S},seed=float.fromhex(\'{seed}\')'.format(S=self.S, seed=self.seed.hex())

    def setUp(self):
        self.setUpInstance(seccs.SecCSLite)

    def setUpInstance(self, seccs_class):
        kvs = dict()
        ref_kvs = dict()

        crypto_wrapper = seccs.crypto_wrapper.SHA_256()

        self.digest_size = crypto_wrapper.DIGEST_SIZE

        ''' functions that provide storage consumption information '''
        self.kvs_size = lambda: reduce(
            lambda size, (key, value): size + len(key) + len(value), kvs.items(), 0)
        self.kvs_count = lambda: len(kvs)
        self.rc_count = lambda: len(ref_kvs)

        self.kvs = kvs
        self.ref_kvs = ref_kvs

        ''' initialize SecCSLite '''
        self.seccs = seccs_class(
            self.S, kvs, crypto_wrapper, reference_counter=seccs.rc.DatabaseReferenceCounter(ref_kvs))
        self.R = self.seccs._R

    def tearDown(self):
        ''' delete references to data structure and force garbage collection '''
        del self.kvs_size
        del self.kvs_count
        del self.rc_count
        del self.kvs
        del self.ref_kvs
        del self.seccs
        del self.R
        del self.digest_size

        import gc
        gc.collect()

    def test_unsupported_chunksize(self):
        kvs = dict()
        crypto_wrapper = seccs.crypto_wrapper.SHA_256()
        self.assertRaises(
            seccs.UnsupportedChunkSizeError, seccs.SecCSLite, 63, kvs, crypto_wrapper)

    '''
    G1: The (expected) increase of the data structure's storage consumption caused by PutContent(m) should be in O(|m|).
    '''
    #@unittest.skip("not now")

    def test_small_inserts(self):
        ''' data structure should be empty at the beginning '''
        kvs_size = self.kvs_size()
        self.assertEqual(kvs_size, 0)
        kvs_count = self.kvs_count()
        self.assertEqual(kvs_count, 0)
        rc_count = self.rc_count()
        self.assertEqual(rc_count, 0)

        ''' verify that contents up to the average chunk size are stored in a single chunk '''
        for content_length in range(0, self.S + 1):
            content = ''.join(chr(self.random.randint(0, 255))
                              for _ in range(content_length))
            self.seccs.put_content(content)

            kvs_size += content_length + self.digest_size
            kvs_count += 1
            rc_count += 1

            self.assertEqual(self.kvs_size(), kvs_size)
            self.assertEqual(self.kvs_count(), kvs_count)
            self.assertEqual(self.rc_count(), rc_count)

        ''' verify that contents beyond the average chunk size are stored in more than one chunk '''
        content = ''.join(chr(self.random.randint(0, 255))
                          for _ in range(self.S + 1))
        self.seccs.put_content(content)

        kvs_size += content_length + self.digest_size
        kvs_count += 1
        rc_count += 1

        self.assertGreater(self.kvs_size(), kvs_size)
        self.assertGreater(self.kvs_count(), kvs_count)
        self.assertGreater(self.rc_count(), rc_count)

    #@unittest.skip("not now")
    def test_large_inserts(self):
        ''' data structure should be empty at the beginning '''
        kvs_size = self.kvs_size()
        self.assertEqual(kvs_size, 0)
        kvs_count = self.kvs_count()
        self.assertEqual(kvs_count, 0)
        rc_count = self.rc_count()
        self.assertEqual(rc_count, 0)

        ''' verify for content lengths of different orders of magnitude '''
        for chunking_levels in range(1, 8):
            content_length = self.random.randint(
                int(self.S * (self.S / self.R)**(chunking_levels - 1)), int(self.S * (self.S / self.R)**(chunking_levels)))

            ''' averaged over 10 insertions, it is unlikely that a content's storage costs are above four times of its expected storage costs '''
            expected_costs = (content_length / self.S) * (self.S +
                                                          self.digest_size) * 2  # storage for leaf chunks times two
            for _ in range(10):
                content = ''.join(chr(self.random.randint(0, 255))
                                  for _ in range(content_length))
                self.seccs.put_content(content)

                kvs_size += 4 * expected_costs

            self.assertLess(self.kvs_size(), kvs_size)
            kvs_size = self.kvs_size()

    '''
    G2: If m is highly redundant, i.e. there exists another m' in the content store that
        is identical to m except for a single sequence of d bytes, the (expected) increase
        in storage consumption caused by PutContent(m) should be in O(d + log|m|).
    '''
    #@unittest.skip("not now")

    def test_similar_contents(self):
        ''' data structure should be empty at the beginning '''
        kvs_size = self.kvs_size()
        self.assertEqual(kvs_size, 0)
        kvs_count = self.kvs_count()
        self.assertEqual(kvs_count, 0)
        rc_count = self.rc_count()
        self.assertEqual(rc_count, 0)

        ''' verify for content lengths of different orders of magnitude '''
        for chunking_levels in range(1, 8):
            content_length = self.random.randint(
                int(self.S * (self.S / self.R)**(chunking_levels - 1)), int(self.S * (self.S / self.R)**(chunking_levels)))

            ''' choose random offset '''
            offset = self.random.randint(0, content_length)

            ''' choose random d '''
            d = self.random.randint(
                1, content_length / 10 + 1)  # should be at least an order of magnitude less than the length

            increase_size = 0
            expected_increase = 0

            ''' average over 10 runs '''
            for _ in range(10):
                content = ''.join(chr(self.random.randint(0, 255))
                                  for _ in range(content_length))
                self.seccs.put_content(content)
                kvs_size = self.kvs_size()

                content = ''.join([content[:offset], ''.join(
                    chr(self.random.randint(0, 255)) for _ in range(d)), content[offset + d:]])
                self.seccs.put_content(content)

                increase_size += self.kvs_size() - kvs_size

                ''' calculate expected increase '''
                expected_increase += 4 * \
                    ((math.ceil(math.log(content_length / self.S) /
                                math.log(self.S / self.R)) + 1) * (self.S + self.digest_size) + d)

            self.assertLess(increase_size, expected_increase)
            kvs_size = self.kvs_size()

    '''
    G3: If any call k = PutContent(m) has been issued before m2 = GetContent(k), then it holds m2 = m or an Exception is raised.
    '''
    #@unittest.skip("not now")

    def test_small_retrievals(self):
        ''' verify contents up to the average chunk size that are stored in a single chunk '''
        for content_length in range(0, self.S + 1):
            content = ''.join(chr(self.random.randint(0, 255))
                              for _ in range(content_length))
            k = self.seccs.put_content(content)

            m = self.seccs.get_content(k)
            self.assertEqual(m, content)

    #@unittest.skip("not now")
    def test_large_retrievals(self):
        ''' verify for content lengths of different orders of magnitude '''
        for chunking_levels in range(1, 8):
            content_length = self.random.randint(
                int(self.S * (self.S / self.R)**(chunking_levels - 1)), int(self.S * (self.S / self.R)**(chunking_levels)))

            content = ''.join(chr(self.random.randint(0, 255))
                              for _ in range(content_length))
            k = self.seccs.put_content(content)

            m = self.seccs.get_content(k)
            self.assertEqual(m, content)

    '''
    G4: After DeleteContent(k) has been executed, the content store shall be in
    the same state as it would have been if neither that nor the most recent
    PutContent call that returned k had been made.
    '''
    #@unittest.skip("not now")

    def test_simple_immediate_deletion(self):
        ''' verify (insert a, delete a) vs. () '''

        ''' record data structure state '''
        kvs = dict(self.kvs)
        ref_kvs = dict(self.ref_kvs)

        ''' insert and delete contents of lengths of different orders of magnitude '''
        for chunking_levels in range(1, 8):
            content_length = self.random.randint(
                int(self.S * (self.S / self.R)**(chunking_levels - 1)), int(self.S * (self.S / self.R)**(chunking_levels)))

            content = ''.join(chr(self.random.randint(0, 255))
                              for _ in range(content_length))

            ''' insert and delete immediately afterwards '''
            k = self.seccs.put_content(content)
            self.seccs.delete_content(k)

            self.assertEqual(self.kvs, kvs)
            self.assertEqual(self.ref_kvs, ref_kvs)

    #@unittest.skip("not now")
    def test_simple_nonimmediate_deletion(self):
        ''' verify (insert a) vs. (insert b, insert a, delete b) '''

        kvs_empty = dict(self.kvs)
        ref_kvs_empty = dict(self.ref_kvs)

        ''' insert some content and record data structure state '''
        content_a = ''.join(chr(self.random.randint(0, 255))
                            for _ in range(2 * 1024 * 1024))
        k_a = self.seccs.put_content(content_a)

        kvs_with_a = dict(self.kvs)
        ref_kvs_with_a = dict(self.ref_kvs)

        ''' delete other content and ensure that data structure is empty again '''
        self.seccs.delete_content(k_a)
        self.assertEqual(self.kvs, kvs_empty)
        self.assertEqual(self.ref_kvs, ref_kvs_empty)

        ''' insert some content b, then a, then delete b '''
        content_b = ''.join(chr(self.random.randint(0, 255))
                            for _ in range(2 * 1024 * 1024))
        k_b = self.seccs.put_content(content_b)

        self.seccs.put_content(content_a)

        self.seccs.delete_content(k_b)

        ''' data structure must be in the same state as it would have been if only a was inserted '''
        self.assertEqual(self.kvs, kvs_with_a)
        self.assertEqual(self.ref_kvs, ref_kvs_with_a)

    #@unittest.skip("not now")
    def test_complex_nonimmediate_deletion(self):
        ''' verify (insert a) vs. (insert b, insert a, delete b) with b being a slightly modified version of a '''

        kvs_empty = dict(self.kvs)
        ref_kvs_empty = dict(self.ref_kvs)

        ''' insert some content and record data structure state '''
        content_a = ''.join(chr(self.random.randint(0, 255))
                            for _ in range(2 * 1024 * 1024))
        k_a = self.seccs.put_content(content_a)

        kvs_with_a = dict(self.kvs)
        ref_kvs_with_a = dict(self.ref_kvs)

        ''' delete other content and ensure that data structure is empty again '''
        self.seccs.delete_content(k_a)
        self.assertEqual(self.kvs, kvs_empty)
        self.assertEqual(self.ref_kvs, ref_kvs_empty)

        ''' insert some content b, then a, then delete b '''
        offset = self.random.randint(0, len(content_a))
        d = self.random.randint(1, len(content_a) / 10 + 1)
        content_b = ''.join([content_a[:offset], ''.join(
            chr(self.random.randint(0, 255)) for _ in range(d)), content_a[offset + d:]])
        k_b = self.seccs.put_content(content_b)

        self.seccs.put_content(content_a)

        self.seccs.delete_content(k_b)

        ''' data structure must be in the same state as it would have been if only a was inserted '''
        self.assertEqual(self.kvs, kvs_with_a)
        self.assertEqual(self.ref_kvs, ref_kvs_with_a)

    #@unittest.skip("not now")
    def test_multiple_deletion(self):
        ''' verify (insert a, insert a, delete a, delete a) vs. () '''

        ''' record data structure state '''
        kvs = dict(self.kvs)
        ref_kvs = dict(self.ref_kvs)

        ''' insert and delete contents of lengths of different orders of magnitude '''
        for chunking_levels in range(1, 8):
            content_length = self.random.randint(
                int(self.S * (self.S / self.R)**(chunking_levels - 1)), int(self.S * (self.S / self.R)**(chunking_levels)))

            content = ''.join(chr(self.random.randint(0, 255))
                              for _ in range(content_length))

            ''' insert and delete immediately afterwards '''
            k = self.seccs.put_content(content)
            k2 = self.seccs.put_content(content)

            self.assertEqual(k, k2)

            self.seccs.delete_content(k)
            self.seccs.delete_content(k2)

            self.assertEqual(self.kvs, kvs)
            self.assertEqual(self.ref_kvs, ref_kvs)

    #@unittest.skip("not now")
    def test_deletion_after_multiple_insertion(self):
        ''' verify (insert a, insert a, delete a) vs. (insert_a) '''

        kvs_empty = dict(self.kvs)
        ref_kvs_empty = dict(self.ref_kvs)

        ''' insert some content and record data structure state '''
        content_a = ''.join(chr(self.random.randint(0, 255))
                            for _ in range(2 * 1024 * 1024))
        k_a = self.seccs.put_content(content_a)

        kvs_with_a = dict(self.kvs)
        ref_kvs_with_a = dict(self.ref_kvs)

        ''' delete other content and ensure that data structure is empty again '''
        self.seccs.delete_content(k_a)
        self.assertEqual(self.kvs, kvs_empty)
        self.assertEqual(self.ref_kvs, ref_kvs_empty)

        ''' insert some content a, then a again, then delete a '''
        k_a = self.seccs.put_content(content_a)

        k_a2 = self.seccs.put_content(content_a)
        self.seccs.delete_content(k_a2)

        ''' data structure must be in the same state as it would have been if only a was inserted '''
        self.assertEqual(self.kvs, kvs_with_a)
        self.assertEqual(self.ref_kvs, ref_kvs_with_a)

if __name__ == "__main__":

    ''' list of chunk sizes that should be evaluated '''
    CHUNK_SIZES = [128]

    ''' list of seeds that triggered an error in the past '''
    REQUIRED_SEEDS = [
        float.fromhex('0x1.81c6d350b9a20p-6'),
        float.fromhex('0x1.6221d735fc060p-1'),
        float.fromhex('0x1.1e20ca763865ep-1'),
        float.fromhex('0x1.c17016a32c630p-3'),
        float.fromhex('0x1.c9dd7b04184f8p-2'),
        float.fromhex('0x1.1431bafbf716ap-1'),
        float.fromhex('0x1.7b5da4558c9dep-2')
    ]

    ''' number of seeds to be chosen randomly '''
    RANDOM_TESTS_COUNT = 1

    ''' execute all tests with required seeds and RANDOM_TESTS_COUNT randomly chosen seeds '''
    suite = unittest.TestSuite()
    for cls in [RCTest, CryptoWrapperTest]:
        for name in unittest.TestLoader().getTestCaseNames(cls):
            suite.addTest(cls(name))
    for seed in REQUIRED_SEEDS + [None] * RANDOM_TESTS_COUNT:
        for S in CHUNK_SIZES:
            for name in unittest.TestLoader().getTestCaseNames(SecCSLiteTest):
                suite.addTest(SecCSLiteTest(name, S=S, seed=seed)
                              if seed is not None else SecCSLiteTest(name, S=S))
    unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
