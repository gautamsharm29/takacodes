# Payment Logic Analysis Report

## Overview
This report details the findings from a static analysis of the `base` (DEX) and `split_config.arm64_v8a` (Native Library) files. It focuses on identifying logic errors, architectural flaws, and client-side trust issues that pose a **Direct Financial Threat** to the platform or its users.

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
| **Account Takeover** | **H5 Bridge Exploit** | `LWChat_MobileJsInterface` | Malicious web pages trigger app actions (payment, gifting). | **High** |
| **Discount Abuse** | **Rebate Manipulation** | `setTotalRebate` | Clients define their own discount/rebate amounts. | **Medium** |

## Technical Root Cause Analysis (Defensive Mechanics)

This section explains the *technical reason* why these bugs exist, helping developers understand the flaw in the logic flow.

### 1. The "Negative Value Injection" Logic Flaw
*   **The Flaw**: Missing Input Sanitization + Signed Integer Arithmetic.
*   **Mechanism**: The server receives a JSON object (e.g., `{ "amount": -100 }`). Most backend languages (Java, Go, Node.js) parse numbers as signed integers by default. If the business logic is simply `User.balance -= Request.amount`, the operation becomes `User.balance -= -100`, which mathematically equals `User.balance += 100`.
*   **Defensive Fix**: The server must explicitly validate `if (Request.amount <= 0) return ERROR;` *before* touching any balance logic.

### 2. The "Receipt Spoofing" Architecture Flaw
*   **The Flaw**: Client-Side Trust for Verification Data.
*   **Mechanism**: The verification process relies on the client to send the `PurchaseToken` and `OrderID`. A malicious client can send a token from a previous ($0.99) transaction while requesting the fulfillment of a large ($99.99) item. If the server only asks Google "Is this token valid?" without asking "Has this token been used before?" or "Does this token match the item being claimed?", the check passes.
*   **Defensive Fix**: The server must store `used_tokens` in a database (idempotency) and verify that `Google.ProductID == Request.ItemID`.

### 3. The "Client-Side Pricing" Logical Error
*   **The Flaw**: Price Authority Delegation.
*   **Mechanism**: The application sends the *price* of the call/gift in the API request (e.g., `LWChat_LinkPriceBean`). This delegates authority to the client. A malicious client simply changes the number before sending.
*   **Defensive Fix**: The client should only send the `TargetUserID` or `GiftID`. The server must look up the current rate/price from its own trusted database.

### 4. The "Biometric Bypass" Configuration Error
*   **The Flaw**: insecure Default Configuration + Debug Artifacts.
*   **Mechanism**:
    1.  `TxyHyYtSDKSettings.json` has `need_encrypt: false`. This allows Man-in-the-Middle attackers to replace the video stream sent to the verification server.
    2.  `libst_mobile.so` exports `st_mobile_enable_debug_mode`. Debug modes often disable liveness checks (to allow devs to test with static images).
*   **Defensive Fix**: Enable encryption in JSON config and strip debug symbols from the native library during the build process (`strip --strip-debug`).

## Detailed Vulnerability Analysis

### [Previously Identified Vulnerabilities Retained Here]

### New Finding: Rebate/Voucher Manipulation
*   **Description**: Analysis found `setTotalRebate` and `voucherExpireTime` in the context of `LWChat_GiftChooseBean`.
*   **The Flaw**: If the client is responsible for calculating the "Total Rebate" (e.g., applying a coupon locally) and sending the final discounted price to the server, an attacker can set `totalRebate` to 100% (free) or manipulate the expiration time to use expired vouchers.
*   **Financial Threat**: Users obtain items at unauthorized discounts.

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

5.  **WebView Security**:
    *   **Origin Checks**: Ensure `addJavascriptInterface` is only enabled for trusted domains.

## Tools Provided
*   `analyze_payment.py`: A Python script to perform static analysis on future builds to detect these patterns.
