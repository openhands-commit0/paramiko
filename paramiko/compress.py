"""
Compression implementations for a Transport.
"""
import zlib

class ZlibCompressor:

    def __init__(self):
        self.z = zlib.compressobj()

    def __call__(self, data):
        return self.z.compress(data) + self.z.flush(zlib.Z_FULL_FLUSH)

class ZlibDecompressor:

    def __init__(self):
        self.z = zlib.decompressobj()

    def __call__(self, data):
        return self.z.decompress(data)