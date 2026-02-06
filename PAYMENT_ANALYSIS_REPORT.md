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

## Detailed Vulnerability Analysis

### 1. Negative Value Injection (The "Inverted Transaction" Bug)
*   **Description**: The application uses a client-constructed object, `LWChat_SendPayMessageBean`, which contains a `messageAmount` field.
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
*   **The Flaw**: Trusting the client to declare the price of a service allows the client to dictate the transaction terms.
*   **Financial Threat**:
    *   **Free Service**: An attacker modifies the price to `0` to use premium services for free.
    *   **Griefing**: An attacker modifies the price to an exorbitant amount when another user initiates a call (if IDOR exists), draining the victim's wallet.

### 4. Wage & Activity Simulation
*   **Description**: The `LWChat_HourlyWageInfoBean` suggests that "billable hours" or activity metrics are reported by the client app.
*   **The Flaw**: Activity tracking that relies on client reports (rather than server-side session monitoring) is easily spoofed.
*   **Financial Threat**: The platform pays out real money (wages) to users who are not actually performing the work (e.g., running a bot to send "I am active" packets 24/7).

### 5. Biometric Verification Bypass (Identity Fraud)
*   **Description**: Face verification logic involves `LWChat_FaceKycAuthAo` (client-side auth object) and native libraries with debug modes enabled (`st_mobile_enable_debug_mode`).
*   **The Flaw**:
    *   **Debug Mode**: Can disable liveness checks (blink/turn head), allowing static photos to pass.
    *   **Client Trust**: If the server trusts the `FaceKycAuthAo` object without a cryptographic proof (signed token) from the SDK provider, the check is skipped entirely.
*   **Financial Threat**: Fraudsters can verify fake accounts to abuse "New User Bonuses", "Cash Out" restrictions, or commit credit card fraud using stolen identities.

## Referral System Security Assessment

This section analyzes the "Invite" and "Referral" mechanisms for potential abuse.

### 1. Self-Referral Bypasses
*   **Artifacts**: String `str_you_can_not_invite_your_self`.
*   **Analysis**: The existence of this string implies the **Client** performs the check to prevent a user from entering their own referral code.
*   **The Flaw**: If this check is *only* on the client, an attacker can simply modify the request (or the app) to bypass it. They can create a new account and bind their *own* main account's code, farming rewards for themselves.

### 2. Device ID Spoofing (Infinite Invites)
*   **Artifacts**: `checkDeviceIds` method found in DEX.
*   **Analysis**: Referral systems often limit "One Invite per Device" to prevent farming.
*   **The Flaw**: Device IDs (IMEI, Android ID, Mac Address) are easily spoofed on rooted devices or emulators. If the server trusts the client-reported Device ID, an attacker can generate thousands of unique IDs, create thousands of fake accounts, and farm "New User Invite Bonuses" repeatedly.

### 3. Reward Claim Replay
*   **Artifacts**: `LWChat_InviteBean`.
*   **The Flaw**: If the endpoint to claim the referral reward is not idempotent, an attacker might capture a valid "Invite Success" request and replay it multiple times to claim the reward x100 for a single invite.

## Recommendations for Remediation

1.  **Enforce Server-Side Authority**:
    *   **Prices**: The server must look up prices from its own database based on the SKU/Service ID. Ignore client-sent price fields.
    *   **Verification**: Validate all receipts directly with Google/Apple APIs.
    *   **Wages**: Calculate wages based on server-side connection logs, not client reports.
    *   **Referrals**: Perform "Self-Referral" checks on the server. Do not trust the client to validate relationships.

2.  **Strict Input Sanitation**:
    *   **Positive Integers**: Reject any transaction request where `amount`, `price`, or `count` is <= 0.
    *   **Bounds Checking**: Ensure exchange rates and conversion amounts are within sane limits.

3.  **Secure Configuration**:
    *   **Disable Debug**: Strip `st_mobile_enable_debug_mode` and other debug symbols from production builds.
    *   **Encrypt Data**: Enable encryption in `TxyHyYtSDKSettings.json` to prevent MitM attacks on verification data.

4.  **Idempotency**: Implement unique request IDs to prevent the replay of reward claims and purchase verifications.

5.  **Referral Fraud Prevention**:
    *   **Device Fingerprinting**: Use robust, server-side device fingerprinting (beyond simple IMEI) to detect farming farms.
    *   **Activity Thresholds**: Only grant referral rewards after the new user reaches a certain activity level (e.g., Level 5 or first purchase) to make farming inefficient.

## Tools Provided
*   `analyze_payment.py`: A Python script to perform static analysis on future builds to detect these patterns.
