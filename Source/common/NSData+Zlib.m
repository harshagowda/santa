/// Copyright 2015 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "NSData+Zlib.h"

#include <zlib.h>

@implementation NSData (Zlib)

+ (BOOL)compressFile:(NSString *)path {
  NSString *gzPath = [path stringByAppendingString:@".gz"];

  gzFile out = gzopen(gzPath.UTF8String, "wb");
  if (!out) {
    return NO;
  }

  NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
  do {
    NSData *d = [fh readDataOfLength:BUFSIZ];
    if (!d.length) break;
    int bytes_written = gzwrite(out, d.bytes, (unsigned int)d.length);
    if (bytes_written == 0) {
      gzclose(out);
      unlink(gzPath.UTF8String);
      return NO;
    }
  } while (1);

  gzclose(out);
  unlink(path.UTF8String);
  return YES;
}

+ (BOOL)decompressFile:(NSString *)path fileHandle:(NSFileHandle *)fh {
  gzFile in = gzopen(path.UTF8String, "rb");
  if (!in) {
    return NO;
  }

  int bytes_read = 0;
  do {
    char buf[BUFSIZ];
    bytes_read = gzread(in, buf, BUFSIZ);
    [fh writeData:[NSData dataWithBytesNoCopy:buf length:bytes_read freeWhenDone:NO]];
  } while (bytes_read);

  [fh closeFile];

  gzclose(in);
  return YES;
}

+ (BOOL)decompressFile:(NSString *)path {
  NSString *nongzPath = [path stringByDeletingPathExtension];
  [[NSFileManager defaultManager] createFileAtPath:nongzPath contents:nil attributes:NULL];
  NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:nongzPath];
  return [self decompressFile:path fileHandle:fh];
}

- (NSData *)compressIncludingGzipHeader:(BOOL)includeHeader {
  if (self.length) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uint)self.length;
    stream.next_in = (Bytef *)self.bytes;
    stream.total_out = 0;
    stream.avail_out = 0;

    NSUInteger chunkSize = 16384;

    int windowSize = 15;
    if (includeHeader) {
      windowSize += 16;
    }

    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION,
                     Z_DEFLATED, windowSize, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
      NSMutableData *data = [NSMutableData dataWithLength:chunkSize];
      while (stream.avail_out == 0) {
        if (stream.total_out >= data.length) {
          data.length += chunkSize;
        }
        stream.next_out = (uint8_t *)data.mutableBytes + stream.total_out;
        stream.avail_out = (uInt)(data.length - stream.total_out);
        deflate(&stream, Z_FINISH);
      }
      deflateEnd(&stream);
      data.length = stream.total_out;
      return data;
    }
  }
  return nil;
}

- (NSData *)zlibCompressed {
  return [self compressIncludingGzipHeader:NO];
}

- (NSData *)gzipCompressed {
  return [self compressIncludingGzipHeader:YES];
}

@end
