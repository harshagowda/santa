/// Copyright 2016 Google Inc. All rights reserved.
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

#import "SNTCommandController.h"

#import <sys/ioctl.h>

#import "GPBUtilities.h"

#import "EventLog.pbobjc.h"
#import "NSData+Zlib.h"

@interface SNTCommandLog : NSObject<SNTCommand>
@end

@implementation SNTCommandLog

REGISTER_COMMAND_NAME(@"log")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Print the contents of protobuf log files.";
}

+ (NSString *)longHelpText {
  return (@"Print out a protobuf-encoded log file.\n"
          @"\n"
          @"Works with raw proto files, gzip files and standard input.\n"
          @"\n"
          @"Examples:\n"
          @"  santactl log /var/db/santa/events.pblog\n"
          @"  santactl log /var/db/santa/events.pblog.1458678410.gz\n"
          @"  cat myproto | santactl log\n"
          @"\n"
          @"Output:\n"
          @"  Output format is currently protobuf text format\n"
          @"  JSON will be supported in future.\n");
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  NSMutableArray *args = [arguments mutableCopy];

  // Check for --count argument.
  BOOL countMode = [args containsObject:@"--count"];
  if (countMode) {
    [args removeObject:@"--count"];
  }

  NSString *path = [args firstObject];
  NSFileHandle *fh;

  // If user didn't specify a path use the default.
  if (!path) {
    path = @"/var/db/santa/events.pblog";
  }

  // Determine whether input source is compressed
  if ([path hasSuffix:@".gz"]) {
    NSPipe *p = [[NSPipe alloc] init];
    fh = [p fileHandleForReading];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
      [NSData decompressFile:path fileHandle:[p fileHandleForWriting]];
    });
  } else {
    fh = [NSFileHandle fileHandleForReadingAtPath:path];
  }

  int64_t count = 0;  

  while (true) {
    @autoreleasepool {
      int32_t length = ReadRawVarint32FromHandle(fh);
      if (length <= 0) break;

      NSData *messageData = [fh readDataOfLength:length];
      SNTEventLogMessage *msg = [SNTEventLogMessage parseFromData:messageData error:NULL];
      if (!msg) break;

      count++;
      if (countMode) continue;
      printf("%lld:\n%s\n", count, GPBTextFormatForMessage(msg, @"  ").UTF8String);
    }
  }

  if (countMode) printf("%lld\n", count);
  exit(0);
}

/**
  This is essentially a copy of ReadRawByteFromData from GPBUtilities
  but reading the data directly from a file handle.
*/
static int8_t ReadRawByteFromHandle(NSFileHandle *fh) {
  NSData *d = [fh readDataOfLength:1];
  if (!d.length) return 0;
  const char *bytes = d.bytes;
  return (int8_t)(bytes[0]);
}

/**
  This is essentially a copy of ReadRawVarint32FromData from GPBUtilities
  but reading the data directly from a file handle.
 
  By the time the value has been read the file handle will be at the beginning
  of the message who's length was just calculated.
*/
static int32_t ReadRawVarint32FromHandle(NSFileHandle *fh) {
  int8_t tmp = ReadRawByteFromHandle(fh);
  if (tmp >= 0) {
    return tmp;
  }
  int32_t result = tmp & 0x7f;
  if ((tmp = ReadRawByteFromHandle(fh)) >= 0) {
    result |= tmp << 7;
  } else {
    result |= (tmp & 0x7f) << 7;
    if ((tmp = ReadRawByteFromHandle(fh)) >= 0) {
      result |= tmp << 14;
    } else {
      result |= (tmp & 0x7f) << 14;
      if ((tmp = ReadRawByteFromHandle(fh)) >= 0) {
        result |= tmp << 21;
      } else {
        result |= (tmp & 0x7f) << 21;
        result |= (tmp = ReadRawByteFromHandle(fh)) << 28;
        if (tmp < 0) {
          // Discard upper 32 bits.
          for (int i = 0; i < 5; i++) {
            if (ReadRawByteFromHandle(fh) >= 0) {
              return result;
            }
          }
          [NSException raise:NSParseErrorException format:@"Unable to read varint32"];
        }
      }
    }
  }
  return result;
}

@end
