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

#import <XCTest/XCTest.h>

#import "NSData+Zlib.h"

@interface NSData_ZlibTests : XCTestCase
@end

@implementation NSData_ZlibTests

- (void)testZlibCompress {
  NSString *file = [[NSBundle bundleForClass:[self class]] pathForResource:@"dn" ofType:@"plist"];
  NSData *d = [NSData dataWithContentsOfFile:file];

  NSData *dCompressed = [d zlibCompressed];
  NSString *dCompressedB64 = [dCompressed base64EncodedStringWithOptions:0];

  XCTAssertEqualObjects(dCompressedB64,
                        @"eJxVkEuPgkAQhM/wK1juMkDWxN2ghseAGHAZBQRuCARdngF0lF+/I3rZUyeVrvq6"
                        @"Wlrfq5K5ZV1/aeolK3A8y2R10qSXOl+ynqvPFux6RUsf2o/qhg5k2vLSD4zjKZap"
                        @"MuwMALltywwAzdUYxzIPLkMyAIA7lmHPw9B+A4Ax5uLnFpc01XOxB07XtFk3PCwS"
                        @"NiMGLh1SlmBe6f/OIWrcdfFjRVNSGg8xmbZpJDbqsYpCzUfIgHjreyPc2/LCkAUP"
                        @"qjI2feNcmlC4ncTPO/yVkZLvfEVObNWbtJymUKWPkQvPtvJ25Tg8HOd8FGyvUYBy"
                        @"XyyLSCz55KGgdFPk7mZf2IcCb/FEtTRVUWgqFf3xJAqEpQspYZ7qfRuKOh8fv65v"
                        @"7ZZUJZ+5MLSVcCLJGDth4POxOh8JTaSpKDCvofg1kI7gVVIC79YSmJ6yov8A84KC"
                        @"+A==");
}

- (void)testGzipCompress {
  NSString *file = [[NSBundle bundleForClass:[self class]] pathForResource:@"dn" ofType:@"plist"];
  NSData *d = [NSData dataWithContentsOfFile:file];

  NSData *dCompressed = [d gzipCompressed];
  NSString *dCompressedB64 = [dCompressed base64EncodedStringWithOptions:0];

  XCTAssertEqualObjects(dCompressedB64,
                        @"H4sIAAAAAAAAA1WQS4+CQBCEz/ArWO4yQNbE3aCGx4AYcBkFBG4IBF2eAXSUX78jet"
                        @"lTJ5Wu+rpaWt+rkrllXX9p6iUrcDzLZHXSpJc6X7Keq88W7HpFSx/aj+qGDmTa8tIP"
                        @"jOMplqky7AwAuW3LDADN1RjHMg8uQzIAgDuWYc/D0H4DgDHm4ucWlzTVc7EHTte0WT"
                        @"c8LBI2IwYuHVKWYF7p/84hatx18WNFU1IaDzGZtmkkNuqxikLNR8iAeOt7I9zb8sKQ"
                        @"BQ+qMjZ941yaULidxM87/JWRku98RU5s1Zu0nKZQpY+RC8+28nblODwc53wUbK9RgH"
                        @"JfLItILPnkoaB0U+TuZl/YhwJv8US1NFVRaCoV/fEkCoSlCylhnup9G4o6Hx+/rm/t"
                        @"llQln7kwtJVwIskYO2Hg87E6HwlNpKkoMK+h+DWQjuBVUgLv1hKYnrKi/wBw31CGqw"
                        @"EAAA==");
}

- (void)testCompressDecompressFile {
  NSString *file = [[NSBundle bundleForClass:[self class]] pathForResource:@"bad_pagezero"
                                                                    ofType:@""];
  NSString *target = [NSTemporaryDirectory() stringByAppendingPathComponent:@"gztest"];
  
  [[NSFileManager defaultManager] copyItemAtPath:file toPath:target error:NULL];

  [NSData compressFile:target];
  [NSData decompressFile:[target stringByAppendingPathExtension:@"gz"]];

  NSData *d1 = [NSData dataWithContentsOfFile:file];
  NSData *d2 = [NSData dataWithContentsOfFile:target];

  XCTAssertEqualObjects(d1, d2);
}

@end
