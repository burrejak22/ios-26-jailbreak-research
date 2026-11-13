#!/bin/bash
# Build and deploy PoCs to iPhone 17 Pro via Xcode command-line tools
#
# Prerequisites:
#   - Xcode installed with iOS 26.x SDK
#   - iPhone connected via USB and trusted
#   - Apple Developer account (free works for personal deployment)
#
# This creates a minimal Xcode project, builds, and deploys.

set -euo pipefail

WORK="$HOME/jb-research/poc-xcode"
TEAM_ID="${APPLE_TEAM_ID:-}" # Set your team ID or we'll try to auto-detect
BUNDLE_PREFIX="com.research.jbpoc"

mkdir -p "$WORK"

echo "=== Creating Xcode project for PoC deployment ==="

# Check for connected devices
echo "Connected devices:"
xcrun xctrace list devices 2>/dev/null | grep -i iphone || \
    instruments -s devices 2>/dev/null | grep -i iphone || \
    echo "(install Xcode command line tools if this fails)"

# Create the project structure
PROJECT="$WORK/JBPoC"
mkdir -p "$PROJECT/JBPoC"

# Info.plist
cat > "$PROJECT/JBPoC/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>JBPoC</string>
    <key>CFBundleIdentifier</key>
    <string>com.research.jbpoc</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>JBPoC</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSRequiresIPhoneOS</key>
    <true/>
    <key>UILaunchStoryboardName</key>
    <string>LaunchScreen</string>
    <key>UISupportedInterfaceOrientations</key>
    <array>
        <string>UIInterfaceOrientationPortrait</string>
    </array>
    <key>UIRequiredDeviceCapabilities</key>
    <array>
        <string>arm64</string>
    </array>
</dict>
</plist>
PLIST

# Entitlements (minimal — no special entitlements needed)
cat > "$PROJECT/JBPoC/JBPoC.entitlements" << 'ENT'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>
ENT

# Main entry point that runs all PoCs
cat > "$PROJECT/JBPoC/main.m" << 'MAIN'
#import <UIKit/UIKit.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@interface PoCViewController : UIViewController
@property (strong, nonatomic) UITextView *logView;
@end

// Redirect NSLog to our text view
static UITextView *g_logView = nil;
static NSMutableString *g_logBuffer = nil;

static void appendLog(NSString *msg) {
    if (!g_logBuffer) g_logBuffer = [NSMutableString new];
    [g_logBuffer appendString:msg];
    [g_logBuffer appendString:@"\n"];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_logView) {
            g_logView.text = [g_logBuffer copy];
            // Auto-scroll to bottom
            NSRange range = NSMakeRange(g_logView.text.length - 1, 1);
            [g_logView scrollRangeToVisible:range];
        }
    });
}

// Include the PoC files
#include "chroot_poc.m"
#include "ave2_poc.m"

@implementation PoCViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    self.logView = [[UITextView alloc] initWithFrame:self.view.bounds];
    self.logView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logView.editable = NO;
    self.logView.font = [UIFont fontWithName:@"Menlo" size:11];
    self.logView.textColor = [UIColor greenColor];
    self.logView.backgroundColor = [UIColor blackColor];
    self.logView.contentInset = UIEdgeInsetsMake(50, 10, 50, 10);
    [self.view addSubview:self.logView];
    g_logView = self.logView;

    // Run PoCs in background
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        appendLog(@"=== iOS Jailbreak Research PoC Suite ===");
        appendLog([NSString stringWithFormat:@"Device: %@", [[UIDevice currentDevice] model]]);
        appendLog([NSString stringWithFormat:@"iOS: %@", [[UIDevice currentDevice] systemVersion]]);
        appendLog(@"");

        // Run chroot PoC (Q1/Q2/Q3)
        appendLog(@"--- Running CVE-2026-43689 (chroot) ---");
        [ChrootPoCController runPoC];
        appendLog(@"");

        // Run AVE2 PoC
        appendLog(@"--- Running CVE-2026-84607 (AppleAVE2) ---");
        [AVE2PoCController runPoC];

        appendLog(@"");
        appendLog(@"=== All PoCs complete ===");
        appendLog(@"Check Console.app on Mac for full NSLog output.");
    });
}

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.rootViewController = [[PoCViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
MAIN

# LaunchScreen storyboard (minimal)
cat > "$PROJECT/JBPoC/LaunchScreen.storyboard" << 'SB'
<?xml version="1.0" encoding="UTF-8"?>
<document type="com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB" version="3.0" toolsVersion="21701" targetRuntime="AppleSDK" propertyAccessControl="none" useAutolayout="YES" launchScreen="YES" useTraitCollections="YES" useSafeAreas="YES" colorMatched="YES" initialViewController="01J-lp-oVM">
    <scenes>
        <scene sceneID="EHf-IW-A2E">
            <objects>
                <viewController id="01J-lp-oVM" sceneMemberID="viewController">
                    <view key="view" contentMode="scaleToFill" id="Ze5-6b-2t3">
                        <rect key="frame" x="0.0" y="0.0" width="393" height="852"/>
                        <autoresizingMask key="autoresizingMask" widthSizable="YES" heightSizable="YES"/>
                        <color key="backgroundColor" systemColor="systemBackgroundColor"/>
                    </view>
                </viewController>
                <placeholder placeholderIdentifier="IBFirstResponder" id="iYj-Kq-Ea1" userLabel="First Responder" sceneMemberID="firstResponder"/>
            </objects>
        </scene>
    </scenes>
</document>
SB

echo ""
echo "=== Project created at $PROJECT ==="
echo ""
echo "To build and deploy:"
echo "  1. Copy chroot_poc.m and ave2_poc.m into $PROJECT/JBPoC/"
echo "  2. Open in Xcode: open $PROJECT (create .xcodeproj manually or use xcodegen)"
echo "  3. Or build from command line — see below"
echo ""
echo "Quick deploy with ios-deploy (brew install ios-deploy):"
echo "  cd $PROJECT"
echo "  # Compile"
echo "  xcrun -sdk iphoneos clang -arch arm64e -framework UIKit -framework Foundation \\"
echo "    -framework VideoToolbox -framework CoreMedia -framework AVFoundation \\"
echo "    -framework IOKit -o JBPoC JBPoC/main.m \\"
echo "    -isysroot \$(xcrun --sdk iphoneos --show-sdk-path)"
echo "  # Sign"
echo "  codesign -s 'Apple Development' --entitlements JBPoC/JBPoC.entitlements JBPoC"
echo "  # Deploy"
echo "  ios-deploy --bundle JBPoC"
