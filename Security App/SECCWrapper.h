//
//  SECCWrapper.h
//  Security App
//
//  Created by Warren Voelkl on 2012-08-11.
//  Copyright (c) 2012 Warren Voelkl. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol ProcessDataDelegate <NSObject>
@required

- (void) appendStringtoOutputText:(NSString *) str;
- (void) processSuccessful:(BOOL) result;

@end

@interface SECCWrapper : NSObject
{
    id <ProcessDataDelegate> delegate;
}

@property (retain) id delegate;

- (void) pingScan;

@end
