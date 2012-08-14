//
//  SECCWrapper.m
//  Security App
//
//  Created by Warren Voelkl on 2012-08-11.
//  Copyright (c) 2012 Warren Voelkl. All rights reserved.
//

#import "SECCWrapper.h"
#include "eventLoop.h"
#include <stdio.h>

@implementation SECCWrapper
@synthesize delegate;

void receiverFunction() {
    
    
    
}


- (void) processUpdate:(NSString *) str
{
    [[self delegate] appendStringtoOutputText: str];
}

- (void) processComplete
{
    [[self delegate] processSuccessful: YES];
}

-(void) pingScan
{
    //@"wtf\n"];
    //[NSTimer scheduledTimerWithTimeInterval:5.0 target:self selector:@selector(processComplete) userInfo:nil repeats:YES];
    NSString* string = [NSString stringWithFormat:@"%s", getPermissionInfo()];
    NSString* string2 = [NSString stringWithFormat:@"%s\n" , pcapLoop()];
     NSString* string3 = [NSString stringWithFormat:@"%s" , setPermissions()];
    [self performSelector:@selector (processUpdate:) withObject:string];
    [self performSelector:@selector (processUpdate:) withObject:string2];
    [self performSelector:@selector (processUpdate:) withObject:string3];
}


@end
