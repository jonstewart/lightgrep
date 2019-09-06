#!/usr/bin/python3

import array
import ctypes
import unittest

import lightgrep


class PointerTests(unittest.TestCase):
    sizes = (0, 1, 7, 8, 1024)
    buftypes = (
        bytes,
        bytearray,
        lambda n: array.array('b', [0]*n),
        lambda n: array.array('B', [0]*n)
    )

    def check_range(self, buf):
        # Is the range the right length?
        r_beg, r_end = lightgrep.buf_range(buf, ctypes.c_char)
        self.assertNotEqual(r_beg, 0)
        self.assertNotEqual(r_end, 0)
        self.assertEqual(ctypes.addressof(r_end)-ctypes.addressof(r_beg), len(buf))

        # Does buf_beg() == buf_range()[0]?
        beg = lightgrep.buf_beg(buf, ctypes.c_char)
        self.assertEqual(ctypes.addressof(beg), ctypes.addressof(r_beg))

        # Does buf_end() == buf_range()[1]?
        end = lightgrep.buf_end(buf, ctypes.c_char)
        self.assertEqual(ctypes.addressof(end), ctypes.addressof(r_end))

    def test_buf_range(self):
        for n in self.sizes:
            for buftype in self.buftypes:
                buf = buftype(n)
                with self.subTest(n=n, buf=buf):
                    self.check_range(buf)
                with self.subTest(n=n, buf=memoryview(buf)):
                    self.check_range(buf)


class HandleTests(unittest.TestCase):
    def test_handle_open_good_closed_bad(self):
        h = lightgrep.Handle(42)
        self.assertTrue(h)
        self.assertEqual(h.handle, 42)
        h.close()
        self.assertFalse(h)
        self.assertEqual(h.handle, None)


class PatternTests(unittest.TestCase):
    def test_pattern_good(self):
        with lightgrep.Error() as err:
            with lightgrep.Pattern() as pat:
                pat.parse("a+b", lightgrep.KeyOpts(), err)

    def test_pattern_bad(self):
        with lightgrep.Error() as err:
            with lightgrep.Pattern() as pat:
                with self.assertRaises(RuntimeError):
                    pat.parse("+", lightgrep.KeyOpts(), err)


if __name__ == "__main__":
    unittest.main()
