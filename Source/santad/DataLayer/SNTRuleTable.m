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

#import "SNTRuleTable.h"

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>

#import "SNTCachedDecision.h"
#import "SNTConfigurator.h"
#import "SNTFileInfo.h"
#import "SNTLogging.h"
#import "SNTRule.h"

// TODO(nguyenphillip): this should be configurable.
// How many rules must be in database before we start trying to remove transitive rules.
static const NSUInteger kTransitiveRuleCullingThreshold = 500000;
// Consider transitive rules out of date if they haven't been used in six months.
static const NSUInteger kTransitiveRuleExpirationSeconds = 6 * 30 * 24 * 3600;

@interface SNTRuleTable ()
@property MOLCodesignChecker *santadCSInfo;
@property MOLCodesignChecker *launchdCSInfo;
@property NSDate *lastTransitiveRuleCulling;
@property NSDictionary *criticalSystemBinaries;
@property(readonly) NSArray *criticalSystemBinaryPaths;
@end

@implementation SNTRuleTable

- (instancetype)init {
  self = [super init];
  if (self) {
    // Save signing info for launchd and santad. Used to ensure they are always allowed.
    self.santadCSInfo = [[MOLCodesignChecker alloc] initWithSelf];
    self.launchdCSInfo = [[MOLCodesignChecker alloc] initWithPID:1];

    // Setup critical system binaries
    [self setupSystemCriticalBinaries];
  }
  return self;
}

- (NSArray *)criticalSystemBinaryPaths {
  return @[
    @"/usr/libexec/trustd", @"/usr/sbin/securityd", @"/usr/libexec/xpcproxy", @"/usr/sbin/ocspd",
    @"/Library/Extensions/santa-driver.kext/Contents/MacOS/santad",
    @"/Library/Extensions/santa-driver.kext/Contents/MacOS/santactl",
    @"/Library/Extensions/santa-driver.kext/Contents/XPCServices/santabs.xpc/Contents/MacOS/santabs",
    @"/Applications/Santa.app/Contents/MacOS/Santa",
  ];
}

- (void)setupSystemCriticalBinaries {
  NSMutableDictionary *bins = [NSMutableDictionary dictionary];
  for (NSString *path in self.criticalSystemBinaryPaths) {
    SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:path];
    MOLCodesignChecker *csInfo = [binInfo codesignCheckerWithError:NULL];

    // Make sure the critical system binary is signed by the same chain as launchd/self
    BOOL systemBin = NO;
    if ([csInfo signingInformationMatches:self.launchdCSInfo]) {
      systemBin = YES;
    }
    if (!systemBin && ![csInfo signingInformationMatches:self.santadCSInfo]) {
      LOGE(@"Unable to validate critical system binary. "
           @"pid 1: %@, santad: %@ and %@: %@ do not match.",
           self.launchdCSInfo.leafCertificate,
           self.santadCSInfo.leafCertificate, path, csInfo.leafCertificate);
      continue;
    }

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];

    cd.decision = SNTEventStateAllowBinary;
    cd.decisionExtra = systemBin ? @"critical system binary" : @"santa binary";
    cd.sha256 = binInfo.SHA256;

    // Not needed, but nice for logging.
    cd.certSHA256 = csInfo.leafCertificate.SHA256;
    cd.certCommonName = csInfo.leafCertificate.commonName;

    bins[binInfo.SHA256] = cd;

  }
  self.criticalSystemBinaries = bins;
}

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
  // Lock this database from other processes
  [[db executeQuery:@"PRAGMA locking_mode = EXCLUSIVE;"] close];

  uint32_t newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'rules' ("
                      @"'shasum' TEXT NOT NULL, "
                      @"'state' INTEGER NOT NULL, "
                      @"'type' INTEGER NOT NULL, "
                      @"'custommsg' TEXT"
                      @")"];
    [db executeUpdate:@"CREATE UNIQUE INDEX rulesunique ON rules (shasum, type)"];

    [[SNTConfigurator configurator] setSyncCleanRequired:YES];

    newVersion = 1;
  }

  if (version < 2) {
    [db executeUpdate:@"DROP VIEW IF EXISTS binrules"];
    [db executeUpdate:@"DROP VIEW IF EXISTS certrules"];
    newVersion = 2;
  }


  if (version < 3) {
    // Add timestamp column for tracking age of transitive rules.
    [db executeUpdate:@"ALTER TABLE 'rules' ADD 'timestamp' INTEGER"];
    newVersion = 3;
  }


  return newVersion;
}

#pragma mark Entry Counts

- (NSUInteger)ruleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules"];
  }];
  return count;
}

- (NSUInteger)binaryRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE type=1"];
  }];
  return count;
}

- (NSUInteger)certificateRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE type=2"];
  }];
  return count;
}

- (NSUInteger)compilerRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE state=?",
             @(SNTRuleStateWhitelistCompiler)];
  }];
  return count;
}

- (NSUInteger)transitiveRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE state=?",
             @(SNTRuleStateWhitelistTransitive)];
  }];
  return count;
}

- (SNTRule *)ruleFromResultSet:(FMResultSet *)rs {
  return [[SNTRule alloc] initWithShasum:[rs stringForColumn:@"shasum"]
                                   state:[rs intForColumn:@"state"]
                                    type:[rs intForColumn:@"type"]
                               customMsg:[rs stringForColumn:@"custommsg"]
                               timestamp:[rs intForColumn:@"timestamp"]];
}

- (SNTRule *)ruleForBinarySHA256:(NSString *)binarySHA256
               certificateSHA256:(NSString *)certificateSHA256 {
  __block SNTRule *rule;

  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs =
        [db executeQuery:
            @"SELECT * FROM rules WHERE (shasum=? and type=1) OR (shasum=? AND type=2) LIMIT 1",
            binarySHA256, certificateSHA256];
    if ([rs next]) {
      rule = [self ruleFromResultSet:rs];
    }
    [rs close];
  }];

  // Allow binaries signed by the "Software Signing" cert used to sign launchd.
  if (!rule && [certificateSHA256 isEqual:self.launchdCSInfo.leafCertificate.SHA256]) {
    rule = [[SNTRule alloc] initWithShasum:certificateSHA256
                                     state:SNTRuleStateWhitelist
                                      type:SNTRuleTypeCertificate
                                 customMsg:nil
                                 timestamp:0];
  }

  return rule;
}

#pragma mark Adding

- (BOOL)addRules:(NSArray *)rules cleanSlate:(BOOL)cleanSlate
           error:(NSError * __autoreleasing *)error {
  if (!rules || rules.count < 1) {
    [self fillError:error code:SNTRuleTableErrorEmptyRuleArray message:nil];
    return NO;
  }

  __block BOOL failed = NO;

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    if (cleanSlate) {
      [db executeUpdate:@"DELETE FROM rules"];
    }

    for (SNTRule *rule in rules) {
      if (![rule isKindOfClass:[SNTRule class]] || rule.shasum.length == 0 ||
          rule.state == SNTRuleStateUnknown || rule.type == SNTRuleTypeUnknown) {
        [self fillError:error code:SNTRuleTableErrorInvalidRule message:rule.description];
        *rollback = failed = YES;
        return;
      }

      if (rule.state == SNTRuleStateRemove) {
        if (![db executeUpdate:@"DELETE FROM rules WHERE shasum=? AND type=?",
                               rule.shasum, @(rule.type)]) {
          [self fillError:error
                     code:SNTRuleTableErrorRemoveFailed
                  message:[db lastErrorMessage]];
          *rollback = failed = YES;
          return;
        }
      } else {
        if (![db executeUpdate:@"INSERT OR REPLACE INTO rules "
                               @"(shasum, state, type, custommsg, timestamp) "
                               @"VALUES (?, ?, ?, ?, ?);",
                               rule.shasum, @(rule.state), @(rule.type), rule.customMsg,
                               @(rule.timestamp)]) {
          [self fillError:error
                     code:SNTRuleTableErrorInsertOrReplaceFailed
                  message:[db lastErrorMessage]];
          *rollback = failed = YES;
          return;
        }
      }
    }
  }];

  return !failed;
}

- (BOOL)addedRulesShouldFlushDecisionCache:(NSArray *)rules {
  // Check for non-plain-whitelist rules first before querying the database.
  for (SNTRule *rule in rules) {
    if (rule.state != SNTRuleStateWhitelist) return YES;
  }

  // If still here, then all rules in the array are whitelist rules.  So now we look for whitelist
  // rules where there is a previously existing whitelist compiler rule for the same shasum.
  // If so we find such a rule, then cache should be flushed.
  __block BOOL flushDecisionCache = NO;
  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    for (SNTRule *rule in rules) {
      // Whitelist certificate rules are ignored
      if (rule.type == SNTRuleTypeCertificate) continue;

      if ([db longForQuery:
           @"SELECT COUNT(*) FROM rules WHERE shasum=? AND type=? AND state=? LIMIT 1",
           rule.shasum, @(SNTRuleTypeBinary), @(SNTRuleStateWhitelistCompiler)] > 0) {
        flushDecisionCache = YES;
        break;
      }
    }
  }];

  return flushDecisionCache;
}

// Updates the timestamp to current time for the given rule.
- (void)resetTimestampForRule:(SNTRule *)rule {
  if (!rule) return;
  [rule resetTimestamp];
  [self inDatabase:^(FMDatabase *db) {
    if (![db executeUpdate:@"UPDATE rules SET timestamp=? WHERE shasum=? AND type=?",
          @(rule.timestamp), rule.shasum, @(rule.type)]) {
      LOGE(@"Could not update timestamp for rule with sha256=%@", rule.shasum);
    }
  }];
}

- (void)removeOutdatedTransitiveRules {
  // Don't attempt to remove transitive rules unless it's been at least an hour since the
  // last time we tried to remove them.
  if (self.lastTransitiveRuleCulling &&
      -[self.lastTransitiveRuleCulling timeIntervalSinceNow] < 3600) return;

  // Don't bother removing rules unless rule database is large.
  if ([self ruleCount] < kTransitiveRuleCullingThreshold) return;
  // Determine what timestamp qualifies as outdated.
  NSUInteger outdatedTimestamp =
      [[NSDate date] timeIntervalSinceReferenceDate] - kTransitiveRuleExpirationSeconds;

  [self inDatabase:^(FMDatabase *db) {
    if (![db executeUpdate:@"DELETE FROM rules WHERE state=? AND timestamp < ?",
          @(SNTRuleStateWhitelistTransitive), @(outdatedTimestamp)]) {
      LOGE(@"Could not remove outdated transitive rules");
    }
  }];

  self.lastTransitiveRuleCulling = [NSDate date];
}

//  Helper to create an NSError where necessary.
//  The return value is irrelevant but the static analyzer complains if it's not a BOOL.
- (BOOL)fillError:(NSError **)error code:(SNTRuleTableError)code message:(NSString *)message {
  if (!error) return NO;

  NSMutableDictionary *d = [NSMutableDictionary dictionary];
  switch (code) {
    case SNTRuleTableErrorEmptyRuleArray:
      d[NSLocalizedDescriptionKey] = @"Empty rule array";
      break;
    case SNTRuleTableErrorInvalidRule:
      d[NSLocalizedDescriptionKey] =
          [NSString stringWithFormat:@"Rule array contained invalid entry: %@", message];
      break;
    case SNTRuleTableErrorInsertOrReplaceFailed:
      d[NSLocalizedDescriptionKey] = @"A database error occurred while inserting/replacing a rule";
      break;
    case SNTRuleTableErrorRemoveFailed:
      d[NSLocalizedDescriptionKey] = @"A database error occurred while deleting a rule";
      break;
  }

  if (message) d[NSLocalizedFailureReasonErrorKey] = message;

  *error = [NSError errorWithDomain:@"com.google.santad.ruletable" code:code userInfo:d];
  return YES;
}

@end
