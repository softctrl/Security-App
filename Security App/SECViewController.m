//
//  SECViewController.m
//  Security App
//
//  Created by Warren Voelkl on 2012-08-10.
//  Copyright (c) 2012 Warren Voelkl. All rights reserved.
//

#import "SECViewController.h"
#import "SECCWrapper.h"

@interface SECViewController ()

@end

@implementation SECViewController
@synthesize outputTextString = _outputTextString;
@synthesize outputText;
- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidUnload
{
    [self setOutputText:nil];
        [super viewDidUnload];
    // Release any retained subviews of the main view.
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return YES;
}

- (IBAction)startButton:(id)sender {
    protocolTest = [[SECCWrapper alloc] init];
    [protocolTest setDelegate:self];
    [protocolTest pingScan];
}

- (void) appendStringtoOutputText:(NSString *) str
{
    self.outputTextString = self.outputText.text;
    NSString *textString = self.outputTextString;
    
    NSString *out = [[NSString alloc] initWithFormat:@"%@%@", textString, str];
                     //[NSString stringWithUTF8String:str]];
    self.outputText.text = out;

    
}

- (void) processSuccessful:(BOOL) result
{
    NSLog(@"wtf");
} 


@end
