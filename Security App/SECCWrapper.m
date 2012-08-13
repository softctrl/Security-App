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

void receiverFunction(const char *filename) {
    FILE *file = NULL;
    if ((file = fopen(filename, "w")) == NULL) {
        return;
    }
    printf("Reciever started\n");
    //pcapLoop(file);
    
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
    //[self performSelector:@selector (processUpdate:) withObject:@"wtf\n"];
    //[NSTimer scheduledTimerWithTimeInterval:5.0 target:self selector:@selector(processComplete) userInfo:nil repeats:YES];
    receiverFunction("blah");
    
}


@end
