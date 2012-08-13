//
//  SECViewController.h
//  Security App
//
//  Created by Warren Voelkl on 2012-08-10.
//  Copyright (c) 2012 Warren Voelkl. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "SECCWrapper.h"

@interface SECViewController : UIViewController <UIApplicationDelegate, ProcessDataDelegate>
{
    SECCWrapper *protocolTest;
}
- (IBAction)startButton:(id)sender;
@property (weak, nonatomic) IBOutlet UITextView *outputText;
@property (copy, nonatomic) NSString *outputTextString;

@end
