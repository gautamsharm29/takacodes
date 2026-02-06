# Payment Logic Analysis Report

## Overview
This report details the findings from a static analysis of the `base` (DEX) and `split_config.arm64_v8a` (Native Library) files, focusing on payment logic, bypass mechanisms, and potential vulnerabilities related to "internal coins", "beans", and direct financial loss.

## Methodology
A custom Python analysis tool (`analyze_payment.py`) was developed and deployed to:
1.  Scan DEX files for payment-related class names and method signatures.
2.  Extract and analyze strings from `.so` (native) libraries for sensitive keywords (pay, bypass, debug, verify).
3.  Identify potentially insecure configurations and debug artifacts.

## Key Findings

### 1. Payment Bypass & Debug Logic
*   **DEX Analysis**:
    *   Found `BypassPolicyLockoutSafetyCheck` string in `base/classes.dex`. This suggests a mechanism exists to bypass security checks, possibly intended for testing but dangerous if accessible in production.
    *   Presence of `free_card_layout` and `free_form` suggests UI paths for free items that could be exploited if logic checks are insufficient.
    *   **Vulnerability**: If `BypassPolicyLockoutSafetyCheck` can be triggered (e.g., via a specific intent, deep link, or modified preference), it could disable safety locks on payment or account policies.

*   **Native Library Analysis (`libliteavsdk.so`)**:
    *   Found strings `kTapAiInferenceTooMuchErrorAutoByPass` and `kTapAiOverTimeAutoByPass`.
    *   **Vulnerability**: These suggest that if the AI/security check system is overloaded or times out, it *fails open* (automatically bypasses the check). An attacker could intentionally induce lag or resource exhaustion to bypass these checks.

### 2. Google Play Billing Implementation
*   **Classes Identified**:
    *   `com/pay/lwchat_pay/lwchat_requestAo/LWChat_GoogleCheckAo`
    *   `com/pay/lwchat_pay/lwchat_response/LWChat_GPTokenAndOrderId`
*   **Logic Flaw**: The existence of a request object specifically for "Google Check" (`LWChat_GoogleCheckAo`) implies the client is responsible for bundling verification data to send to the server.
*   **Risk**: If the server-side implementation of `LWChat_GoogleCheckAo` processing only verifies the format of the token/order ID but fails to validate the receipt directly with the Google Play Developer API, the system is vulnerable to **Receipt Spoofing** and **Replay Attacks**.

### 3. Insecure configurations in Native Libraries
*   **Encryption Disabled**:
    *   `libliteavsdk.so` contains the string: `Payload private encryption is disabled by server config!`.
    *   **Risk**: If "payload private encryption" refers to the protection of payment or sensitive user data within the streaming/interaction protocol, disabling it exposes this data to Man-in-the-Middle (MitM) attacks.

*   **Debug Modes Left Enabled**:
    *   `libst_mobile.so`: `st_mobile_enable_debug_mode`.
    *   `libZegoExpressEngine.so`: `zego_express_enable_debug_assistant`.
    *   **Risk**: Exposed debug functions can often be hooked or called to alter application state, dump memory, or bypass validation routines.

### 4. Internal Currency ("Beans", "Coins")
*   **Classes**:
    *   `com/lwchat/calltab/data/LWChat_RechargeConfigBean`
    *   `com/lwchatlw/lwchat/common/bean/LWChat_LinkPriceBean`
*   **Risk**: The `LinkPriceBean` suggests the price for "links" (calls/interactions) might be handled on the client side (as a "Bean" usually implies a data object). If the client calculates the cost and sends it to the server, an attacker could modify the price to 0 or a negative number.

## Recommendations for Remediation

1.  **Server-Side Validation**: Ensure all Google Play receipts (`LWChat_GoogleCheckAo`) are validated strictly against the Google Play Developer API on the server. Never trust the client's assertion of validity.
2.  **Remove Debug Code**: Strip symbols and disable debug modes (`st_mobile_enable_debug_mode`, `BypassPolicyLockoutSafetyCheck`) in the release build.
3.  **Fail Secure**: Change the logic for `kTapAi...AutoByPass` to "Fail Closed" (deny access) instead of "Fail Open" (bypass) when errors or timeouts occur.
4.  **Enable Encryption**: Re-enable payload encryption in the server configuration for `libliteavsdk` if it carries sensitive data.
5.  **Obfuscation**: Use stronger obfuscation (e.g., ProGuard/R8 with more aggressive rules) to hide sensitive class names like `LWChat_PayServiceImp` and `LWChat_GoogleCheckAo`.

## Tools Provided
*   `analyze_payment.py`: A Python script to replicate this analysis on future builds.
