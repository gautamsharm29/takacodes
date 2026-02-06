# Payment Logic Analysis Report

## Overview
This report details the findings from a static analysis of the `base` (DEX) and `split_config.arm64_v8a` (Native Library) files. It specifically focuses on identifying logic errors and architectural flaws that pose a **Direct Financial Threat** to the platform or its users.

## Financial Threat Matrix

The following table summarizes the identified vulnerabilities that can lead to direct money loss, unauthorized currency accumulation, or fraudulent payouts.

| Threat Category | Vulnerability | Artifact / Class | Financial Impact | Risk Level |
| :--- | :--- | :--- | :--- | :--- |
| **Revenue Loss** | **Receipt Spoofing** | `LWChat_GoogleCheckAo` | Users obtain premium items/VIP status without paying. | **Critical** |
| **Revenue Loss** | **Client-Side Pricing** | `LWChat_LinkPriceBean` | Services (calls, links) consumed for free or at reduced rates. | **High** |
| **Currency Inflation** | **Negative Value Injection** | `LWChat_SendPayMessageBean` | Users generate currency (Beans) by sending negative amounts. | **Critical** |
| **Currency Inflation** | **Gift Count Manipulation** | `LWChat_SendGiftAo` | Users generate currency by sending negative quantities of gifts. | **Critical** |
| **Fraudulent Payout** | **Wage/Activity Fraud** | `LWChat_HourlyWageInfoBean` | Platform pays wages for fake/simulated activity hours. | **High** |
| **Fraudulent Payout** | **Coin Exchange Rates** | `ExchangeGameCoinsBean` | Users manipulate rates to drain platform reserves. | **High** |
| **Bonus Abuse** | **Referral Fraud** | `LWChat_InviteBean` | Users create fake accounts to farm invite bonuses. | **Medium** |
| **Game Manipulation** | **Reward Reporting** | `ReportLuckyGiftComboInfoAo` | Clients fabricate winning streaks or combo counts. | **Critical** |
| **Privilege Escalation** | **Admin/Mod Access** | `LWChat_SetPrivilegeRequestBean` | Unauthorized users promote themselves to room managers. | **High** |

## Detailed Vulnerability Analysis

### 1. Negative Value Injection (The "Inverted Transaction" Bug)
*   **Description**: The application uses a client-constructed object, `LWChat_SendPayMessageBean`, which contains a `messageAmount` field.
*   **Verification Status**: **High Confidence**. The JNI analysis shows no native-level verification for this bean. The validation appears to rely entirely on Java/DEX logic or the server.
*   **The Flaw**: If the server-side logic subtracts this `messageAmount` from the sender's balance without validating that it is a positive integer, a negative value (e.g., `-100`) results in addition (`Balance - (-100) = Balance + 100`).
*   **Financial Threat**: An attacker can exploit this to mint unlimited internal currency ("Beans"), devaluing the economy and potentially selling the currency on gray markets.

### 2. Receipt Spoofing & Replay
*   **Description**: The verification of Google Play purchases relies on `LWChat_GoogleCheckAo`, a request object sent from the client.
*   **The Flaw**: This architecture implies the client is responsible for bundling the receipt data. Without strict server-side validation (checking `orderId` uniqueness and matching `productId` to the payment amount), the server is blind to the validity of the transaction.
*   **Financial Threat**:
    *   **Spoofing**: Using a valid receipt from a $0.99 transaction to claim a $99.99 item.
    *   **Replay**: Using the same $99.99 receipt multiple times to claim the item repeatedly.

### 3. Client-Side Price Authority
*   **Description**: The price for interactions (e.g., calling an anchor) appears to be transmitted in the request (`LWChat_LinkPriceBean`).
*   **Native Evidence**: Found `nativeOnPriceChangeConfirmationResult`. This suggests that while price changes might have a confirmation callback, the logic is likely event-driven on the client, exposing the state to manipulation before the confirmation is sent.
*   **The Flaw**: Trusting the client to declare the price of a service allows the client to dictate the transaction terms.
*   **Financial Threat**:
    *   **Free Service**: An attacker modifies the price to `0` to use premium services for free.
    *   **Griefing**: An attacker modifies the price to an exorbitant amount when another user initiates a call (if IDOR exists), draining the victim's wallet.

### 4. Wage & Activity Simulation
*   **Description**: The `LWChat_HourlyWageInfoBean` suggests that "billable hours" or activity metrics are reported by the client app.
*   **The Flaw**: Activity tracking that relies on client reports (rather than server-side session monitoring) is easily spoofed.
*   **Financial Threat**: The platform pays out real money (wages) to users who are not actually performing the work (e.g., running a bot to send "I am active" packets 24/7).

### 5. Administrative & Game Logic Vulnerabilities
*   **Gambling/Game Trust**:
    *   **Artifact**: `ReportLuckyGiftComboInfoAo`.
    *   **The Flaw**: The class name "Report...Ao" explicitly suggests the client *reports* the result of a game event (e.g., a "Lucky Gift Combo").
    *   **Threat**: An attacker can forge this request to claim they achieved a "Super Combo" or won a jackpot, triggering a fraudulent payout from the server. The server should *calculate* the result, not accept a report of it.
*   **Privilege Escalation**:
    *   **Artifact**: `LWChat_SetPrivilegeRequestBean(appId=`.
    *   **The Flaw**: This request allows setting privileges. If the `appId` or user context isn't strictly validated against the session's role, a regular user might grant themselves "Manager" or "Admin" privileges for a room.
    *   **Threat**: Room hijacking, kicking legitimate owners, or unlocking paid rooms for free.

## Native Symbol Analysis
*   **Method**: Dumped dynamic symbols from `libRongIMLib.so`, `libliteavsdk.so`, and others using `nm`.
*   **Findings**:
    *   `Java_com_tencent_liteav_trtc_TrtcCloudJni_nativeEnablePayloadPrivateEncryption`: Confirms encryption is controllable via JNI, matching the "Encryption Disabled" risk found in configs.
    *   `nativeOnPriceChangeConfirmationResult`: Confirms client-side involvement in price flows.
    *   **Obfuscation**: Many JNI functions in `libRongIMLib` are obfuscated (e.g., `Java_J_N_M3Wjj5EA`), making reverse engineering harder but not securing the logic itself.
    *   **No Native Validation**: There are no obvious "VerifyReceipt" or "ValidateAmount" symbols in the native layer, reinforcing the finding that validation is either in Java (hookable) or Server-side (must be checked).

## Recommendations for Remediation

1.  **Enforce Server-Side Authority**:
    *   **Prices**: The server must look up prices from its own database based on the SKU/Service ID. Ignore client-sent price fields.
    *   **Verification**: Validate all receipts directly with Google/Apple APIs.
    *   **Wages**: Calculate wages based on server-side connection logs, not client reports.
    *   **Game Results**: The server must invoke the RNG (Random Number Generator) and determine the result. The client should only send "Play" and receive the result.

2.  **Strict Input Sanitation**:
    *   **Positive Integers**: Reject any transaction request where `amount`, `price`, or `count` is <= 0.
    *   **Bounds Checking**: Ensure exchange rates and conversion amounts are within sane limits.

3.  **Secure Configuration**:
    *   **Disable Debug**: Strip `st_mobile_enable_debug_mode` and other debug symbols from production builds.
    *   **Encrypt Data**: Enable encryption in `TxyHyYtSDKSettings.json` to prevent MitM attacks on verification data.

4.  **Access Control**:
    *   **Privilege Checks**: Ensure `SetPrivilegeRequest` checks the *requester's* permission level on the server before applying changes.
    *   **IDOR Prevention**: Verify that the user ID in `ModifyAnchorLinkPriceAo` matches the authenticated session.

## Tools Provided
*   `analyze_payment.py`: A Python script to perform static analysis on future builds to detect these patterns.
