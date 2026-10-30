export interface QuizToken {
  id: string;
  text: string;
  isSuspicious: boolean;
}

export interface QuizScenario {
  id: string;
  title: string;
  category: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  channel: "SMS" | "Email" | "WhatsApp" | "Campus Notice" | "Chat";
  sender: string;
  correctClassification: "Legitimate" | "Suspicious";
  /**
   * Segmented message tokens so users can click/highlight suspicious words or phrases
   * directly inside the message before submitting their verdict.
   */
  segments: QuizToken[];
  explanation: string;
  keyTakeaway: string;
}

export const QUIZ_QUESTION_BANK: QuizScenario[] = [
  // ==========================================================================
  // 1–6: FAKE PRIZES, REWARDS & LOTTERY SCAMS
  // ==========================================================================
  {
    id: "q01-festival-cashback-draw",
    title: "The Festival Cashback Draw",
    category: "Fake Prizes & Rewards",
    difficulty: "Beginner",
    channel: "SMS",
    sender: "+91-98990-XX102",
    correctClassification: "Suspicious",
    segments: [
      { id: "s01-1", text: "CONGRATULATIONS! ", isSuspicious: true },
      { id: "s01-2", text: "Your mobile number has ", isSuspicious: false },
      { id: "s01-3", text: "won a ₹50,000 cash reward", isSuspicious: true },
      { id: "s01-4", text: " in our Mega Lucky Draw. ", isSuspicious: false },
      { id: "s01-5", text: "Claim within 15 minutes", isSuspicious: true },
      { id: "s01-6", text: " at ", isSuspicious: false },
      { id: "s01-7", text: "http://lucky-reward-claim.example/win", isSuspicious: true },
      { id: "s01-8", text: " by entering your UPI details.", isSuspicious: true },
    ],
    explanation:
      "This message combines an unsolicited ₹50,000 lottery lure, an artificial 15-minute countdown, an unencrypted HTTP link on an unverified domain, and a request for UPI details.",
    keyTakeaway: "Unsolicited prize notifications that demand immediate clicks or banking details are classic reward scams.",
  },
  {
    id: "q02-smartphone-spin-wheel",
    title: "Free Flagship Smartphone Spin-Wheel",
    category: "Fake Prizes & Rewards",
    difficulty: "Beginner",
    channel: "WhatsApp",
    sender: "Promo-Deals-Desk (+91-80112-XX409)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s02-1", text: "You are today's ", isSuspicious: false },
      { id: "s02-2", text: "100th lucky visitor selected for a FREE Pro Max Smartphone!", isSuspicious: true },
      { id: "s02-3", text: " Pay only ", isSuspicious: false },
      { id: "s02-4", text: "₹499 express shipping fee now", isSuspicious: true },
      { id: "s02-5", text: " at ", isSuspicious: false },
      { id: "s02-6", text: "http://free-phone-dispatch.example/claim", isSuspicious: true },
      { id: "s02-7", text: " before stock runs out in 10 mins!", isSuspicious: true },
    ],
    explanation:
      "Scammers lure victims with an expensive 'free' gadget and steal ₹499 (plus card/UPI credentials) under the guise of a shipping or customs charge.",
    keyTakeaway: "If a 'free prize' requires an upfront shipping or processing payment, it is a scam.",
  },
  {
    id: "q03-upi-scratch-card-pin",
    title: "Scratch Card Cashback PIN Trap",
    category: "Fake Prizes & Rewards",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "+91-77210-XX831",
    correctClassification: "Suspicious",
    segments: [
      { id: "s03-1", text: "You have received a ", isSuspicious: false },
      { id: "s03-2", text: "₹4,500 festival cashback voucher!", isSuspicious: true },
      { id: "s03-3", text: " Open the collect request link ", isSuspicious: false },
      { id: "s03-4", text: "http://upi-reward-credit.example/collect", isSuspicious: true },
      { id: "s03-5", text: " and ", isSuspicious: false },
      { id: "s03-6", text: "enter your 4-digit UPI PIN to credit the amount", isSuspicious: true },
      { id: "s03-7", text: " into your bank account.", isSuspicious: false },
    ],
    explanation:
      "A UPI PIN is only ever required to SEND money from your account—never to receive money or cashback. Fraudsters send 'Collect Requests' disguised as cashback.",
    keyTakeaway: "You never need to enter your UPI PIN or OTP to receive a reward or refund.",
  },
  {
    id: "q04-telecom-anniversary-gift",
    title: "25GB Free Data Anniversary Forward",
    category: "Fake Prizes & Rewards",
    difficulty: "Beginner",
    channel: "WhatsApp",
    sender: "Forwarded Many Times",
    correctClassification: "Suspicious",
    segments: [
      { id: "s04-1", text: " Jubilee Offer: All users get ", isSuspicious: false },
      { id: "s04-2", text: "90 Days FREE Unlimited 5G Recharge!", isSuspicious: true },
      { id: "s04-3", text: " Activate immediately at ", isSuspicious: false },
      { id: "s04-4", text: "http://free-5g-data-claim.example", isSuspicious: true },
      { id: "s04-5", text: " and ", isSuspicious: false },
      { id: "s04-6", text: "forward this message to 10 WhatsApp groups", isSuspicious: true },
      { id: "s04-7", text: " to unlock your plan.", isSuspicious: false },
    ],
    explanation:
      "Viral WhatsApp forwards promising free mobile recharges use social sharing to harvest phone numbers and lead users to adware or phishing forms.",
    keyTakeaway: "Telecom operators announce plans in their official app, never via 'forward to 10 groups' chain messages.",
  },
  {
    id: "q05-supermarket-gift-survey",
    title: "Grocery Voucher Survey Phish",
    category: "Fake Prizes & Rewards",
    difficulty: "Intermediate",
    channel: "Email",
    sender: "rewards@supermarket-voucher-draw.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s05-1", text: "Dear Shopper, complete our 30-second survey to ", isSuspicious: false },
      { id: "s05-2", text: "claim a guaranteed ₹10,000 grocery gift card.", isSuspicious: true },
      { id: "s05-3", text: " Only 3 vouchers left! ", isSuspicious: true },
      { id: "s05-4", text: "Provide your debit card number and CVV", isSuspicious: true },
      { id: "s05-5", text: " for ₹2 identity verification at ", isSuspicious: false },
      { id: "s05-6", text: "http://voucher-verify-card.example", isSuspicious: true },
    ],
    explanation:
      "Asking for full debit card details and CVV for a '₹2 verification charge' to claim a ₹10,000 voucher is a classic credential-harvesting trap.",
    keyTakeaway: "Never enter your card CVV or banking credentials to claim a survey reward.",
  },
  {
    id: "q06-scholarship-grant-fee",
    title: "National Student Grant Processing Fee",
    category: "Fake Prizes & Rewards",
    difficulty: "Advanced",
    channel: "Email",
    sender: "grant-disbursement@edu-scholarship-fund.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s06-1", text: "Your student profile was auto-selected for a ", isSuspicious: false },
      { id: "s06-2", text: "₹75,000 National Merit Grant", isSuspicious: true },
      { id: "s06-3", text: " without application. To release the bank transfer today, ", isSuspicious: false },
      { id: "s06-4", text: "pay ₹850 file-clearance tax via UPI", isSuspicious: true },
      { id: "s06-5", text: " at ", isSuspicious: false },
      { id: "s06-6", text: "http://grant-release-portal.example/tax", isSuspicious: true },
    ],
    explanation:
      "Real scholarships require formal applications and never charge students an upfront 'file-clearance tax' via UPI to disburse funds.",
    keyTakeaway: "Any scholarship or grant you never applied for that asks for an upfront fee is fraudulent.",
  },

  // ==========================================================================
  // 7–13: PHISHING, KYC, OTP & ACCOUNT VERIFICATION SCAMS
  // ==========================================================================
  {
    id: "q07-kyc-pan-block",
    title: "Urgent Bank KYC & PAN Block",
    category: "OTP & Account Verification",
    difficulty: "Beginner",
    channel: "SMS",
    sender: "+91-70112-XX884",
    correctClassification: "Suspicious",
    segments: [
      { id: "s07-1", text: "Dear Customer, ", isSuspicious: false },
      { id: "s07-2", text: "your bank account will be blocked today", isSuspicious: true },
      { id: "s07-3", text: " because your PAN KYC is expired. ", isSuspicious: false },
      { id: "s07-4", text: "Click immediately to submit OTP:", isSuspicious: true },
      { id: "s07-5", text: " ", isSuspicious: false },
      { id: "s07-6", text: "http://192.168.55.12/kyc-update/login.php", isSuspicious: true },
    ],
    explanation:
      "Sent from a personal 10-digit number, this smishing message threatens same-day account suspension, asks for an OTP, and links to a raw numeric IP address (192.168.55.12) over HTTP.",
    keyTakeaway: "Banks never send KYC update links pointing to raw IP addresses or ask you to submit OTPs to keep an account active.",
  },
  {
    id: "q08-sim-card-24hr-block",
    title: "SIM Card e-KYC Deactivation Alert",
    category: "OTP & Account Verification",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "+91-91234-XX770",
    correctClassification: "Suspicious",
    segments: [
      { id: "s08-1", text: "Telecom Notice: Your ", isSuspicious: false },
      { id: "s08-2", text: "SIM card will be permanently deactivated in 2 hours", isSuspicious: true },
      { id: "s08-3", text: " due to incomplete Aadhaar e-KYC. ", isSuspicious: false },
      { id: "s08-4", text: "Call KYC officer at 88XXXXXX19", isSuspicious: true },
      { id: "s08-5", text: " and ", isSuspicious: false },
      { id: "s08-6", text: "share the 6-digit SMS code", isSuspicious: true },
      { id: "s08-7", text: " to prevent service cutoff.", isSuspicious: false },
    ],
    explanation:
      "Attackers trick victims into sharing an OTP or SIM-swap verification code over the phone by threatening immediate SIM deactivation.",
    keyTakeaway: "Never call personal mobile numbers from KYC SMS alerts or share verification codes over a call.",
  },
  {
    id: "q09-credit-card-points-expiry",
    title: "Reward Points Expiring Tonight",
    category: "Phishing Messages",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "+91-84500-XX210",
    correctClassification: "Suspicious",
    segments: [
      { id: "s09-1", text: "Your 14,800 Credit Card Reward Points (worth ₹3,700) ", isSuspicious: false },
      { id: "s09-2", text: "expire tonight at 11:59 PM.", isSuspicious: true },
      { id: "s09-3", text: " Convert to cash immediately by logging in with ", isSuspicious: false },
      { id: "s09-4", text: "Card Number, CVV & OTP at", isSuspicious: true },
      { id: "s09-5", text: " ", isSuspicious: false },
      { id: "s09-6", text: "http://card-points-redeem-cash.example", isSuspicious: true },
    ],
    explanation:
      "Phishers frequently use expiring credit-card reward points to create urgency and harvest full card numbers, CVVs, and live transaction OTPs.",
    keyTakeaway: "Redeem credit card points only inside your bank's official mobile app or verified net-banking portal.",
  },
  {
    id: "q10-streaming-autopay-failed",
    title: "Streaming Subscription Suspension Lure",
    category: "Phishing Messages",
    difficulty: "Beginner",
    channel: "Email",
    sender: "billing-retry@stream-account-alert.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s10-1", text: "Payment Declined: Your monthly entertainment membership ", isSuspicious: false },
      { id: "s10-2", text: "has been suspended.", isSuspicious: true },
      { id: "s10-3", text: " To avoid losing your profile within 24 hours, ", isSuspicious: true },
      { id: "s10-4", text: "re-enter your credit card CVV and netbanking password", isSuspicious: true },
      { id: "s10-5", text: " at ", isSuspicious: false },
      { id: "s10-6", text: "http://billing-reactivate-now.example/login", isSuspicious: true },
    ],
    explanation:
      "Subscription phishing emails claim a routine billing failure occurred and direct you to a fake HTTP billing page that steals card details and banking passwords.",
    keyTakeaway: "Check subscription status by opening the service's official website or app directly—never through an email link.",
  },
  {
    id: "q11-income-tax-refund-phish",
    title: "Instant Tax Refund Approval Lure",
    category: "Phishing Messages",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "+91-95501-XX612",
    correctClassification: "Suspicious",
    segments: [
      { id: "s11-1", text: "Income Tax Dept: An ", isSuspicious: false },
      { id: "s11-2", text: "instant tax refund of ₹18,450 is approved", isSuspicious: true },
      { id: "s11-3", text: " for your PAN. Account number mismatch detected. ", isSuspicious: false },
      { id: "s11-4", text: "Verify netbanking login & OTP within 1 hour:", isSuspicious: true },
      { id: "s11-5", text: " ", isSuspicious: false },
      { id: "s11-6", text: "http://efiling-refund-claim.example/verify", isSuspicious: true },
    ],
    explanation:
      "Government tax portals do not send SMS messages from personal phone numbers or ask taxpayers to enter net-banking passwords and OTPs on external HTTP links to receive refunds.",
    keyTakeaway: "Verify tax notices only on the official government e-filing portal that you type into your browser yourself.",
  },
  {
    id: "q12-email-mailbox-quota-full",
    title: "Mailbox 99% Full Deactivation Phish",
    category: "OTP & Account Verification",
    difficulty: "Advanced",
    channel: "Email",
    sender: "admin-storage@webmail-quota-upgrade.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s12-1", text: "Warning: Your university email storage has reached 99.8% capacity. ", isSuspicious: false },
      { id: "s12-2", text: "Incoming emails are blocked.", isSuspicious: true },
      { id: "s12-3", text: " Click below to ", isSuspicious: false },
      { id: "s12-4", text: "validate your current password and 2FA code", isSuspicious: true },
      { id: "s12-5", text: " to unlock 50GB free quota: ", isSuspicious: false },
      { id: "s12-6", text: "http://webmail-quota-upgrade.example/auth", isSuspicious: true },
    ],
    explanation:
      "Mailbox quota phishing is one of the most common campus and corporate attacks. Upgrading storage never requires typing your password and 2FA code into an external third-party site.",
    keyTakeaway: "Check storage usage inside your email account settings rather than clicking 'upgrade quota' links in emails.",
  },
  {
    id: "q13-epfo-pf-account-freeze",
    title: "Provident Fund UAN Freeze Alert",
    category: "OTP & Account Verification",
    difficulty: "Advanced",
    channel: "SMS",
    sender: "+91-97110-XX304",
    correctClassification: "Suspicious",
    segments: [
      { id: "s13-1", text: "Important: Your Provident Fund UAN account ", isSuspicious: false },
      { id: "s13-2", text: "will be frozen tonight", isSuspicious: true },
      { id: "s13-3", text: " due to unverified Aadhaar linkage. ", isSuspicious: false },
      { id: "s13-4", text: "Submit Aadhaar OTP and bank password immediately", isSuspicious: true },
      { id: "s13-5", text: " at ", isSuspicious: false },
      { id: "s13-6", text: "http://uan-kyc-reactivate.example", isSuspicious: true },
    ],
    explanation:
      "No official provident fund or banking service ever asks for your bank password alongside an Aadhaar OTP over an unencrypted third-party link.",
    keyTakeaway: "Never combine identity OTPs with banking passwords on links sent via SMS.",
  },

  // ==========================================================================
  // 14–18: SUSPICIOUS LINKS & LEXICAL URL OBFUSCATION
  // ==========================================================================
  {
    id: "q14-subdomain-spoof-cloud",
    title: "Cloud Storage Subdomain Spoof",
    category: "Suspicious Links",
    difficulty: "Advanced",
    channel: "Email",
    sender: "security-alert@mail-account-verify.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s14-1", text: "Security Notice: Your institutional cloud drive password expires in ", isSuspicious: false },
      { id: "s14-2", text: "2 hours.", isSuspicious: true },
      { id: "s14-3", text: " To prevent immediate deletion of your project files, ", isSuspicious: true },
      { id: "s14-4", text: "confirm your current password at ", isSuspicious: true },
      { id: "s14-5", text: "https://university.edu.login-session-check.example/auth", isSuspicious: true },
    ],
    explanation:
      "Notice the clever URL trick: 'university.edu' is placed as a subdomain at the start, while the actual root domain right before the first single slash is 'login-session-check.example'.",
    keyTakeaway: "Even if a URL starts with 'https://' and contains a familiar name, always check the actual root domain right before the first single slash '/'.",
  },
  {
    id: "q15-at-symbol-url-redirect",
    title: "The '@' Symbol Authority Redirect Trick",
    category: "Suspicious Links",
    difficulty: "Advanced",
    channel: "Email",
    sender: "alerts@security-gateway-notice.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s15-1", text: "We detected a login from a new device. ", isSuspicious: false },
      { id: "s15-2", text: "Review and cancel this session within 15 minutes", isSuspicious: true },
      { id: "s15-3", text: " using our secure portal: ", isSuspicious: false },
      { id: "s15-4", text: "https://portal.university.edu@malicious-credential-capture.example/login", isSuspicious: true },
    ],
    explanation:
      "In URL syntax, everything before the '@' symbol is treated as a username, and the browser actually navigates to the host AFTER the '@' symbol (`malicious-credential-capture.example`).",
    keyTakeaway: "Treat any URL containing an '@' symbol in the address bar as highly suspicious.",
  },
  {
    id: "q16-typosquatted-bank-domain",
    title: "Look-Alike Typosquatted Domain",
    category: "Suspicious Links",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "AD-BNKALT",
    correctClassification: "Suspicious",
    segments: [
      { id: "s16-1", text: "Security Alert: Debit card international usage was enabled. ", isSuspicious: false },
      { id: "s16-2", text: "If not you, disable immediately via netbanking:", isSuspicious: true },
      { id: "s16-3", text: " ", isSuspicious: false },
      { id: "s16-4", text: "http://www.onlinesb1-secure-verify.example/disable", isSuspicious: true },
      { id: "s16-5", text: " by entering your ATM PIN.", isSuspicious: true },
    ],
    explanation:
      "Attackers replace the letter 'i' with the number '1' (`onlinesb1`) and append hyphens like `-secure-verify` to trick fast readers into entering their ATM PIN.",
    keyTakeaway: "Watch out for character substitutions (0 for o, 1 for i/l, rn for m) and hyphenated '-secure-verify' domains.",
  },
  {
    id: "q17-shortened-url-invoice",
    title: "Masked Shortened URL Legal Threat",
    category: "Suspicious Links",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "+91-93100-XX540",
    correctClassification: "Suspicious",
    segments: [
      { id: "s17-1", text: "FINAL NOTICE: Overdue traffic challan #DL9941 of ₹2,000 is pending. ", isSuspicious: false },
      { id: "s17-2", text: "Pay within 2 hours to avoid court warrant", isSuspicious: true },
      { id: "s17-3", text: " via quick link: ", isSuspicious: false },
      { id: "s17-4", text: "http://tiny-link.example/challan-pay-99", isSuspicious: true },
    ],
    explanation:
      "Official traffic police e-Challan notifications direct citizens to the official government transport portal (`parivahan.gov.in`), never a shortened link sent from a personal number threatening an immediate warrant.",
    keyTakeaway: "Never pay fines or bills through shortened URLs that hide the true destination domain.",
  },
  {
    id: "q18-malicious-apk-download",
    title: "Fake Banking APK File Download Link",
    category: "Suspicious Links",
    difficulty: "Intermediate",
    channel: "WhatsApp",
    sender: "Customer Care Support (+91-78900-XX112)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s18-1", text: "Dear Customer, to resolve your pending credit card annual fee reversal, ", isSuspicious: false },
      { id: "s18-2", text: "download and install our updated Customer_Support_KYC.apk file", isSuspicious: true },
      { id: "s18-3", text: " from ", isSuspicious: false },
      { id: "s18-4", text: "http://192.168.99.40/downloads/Support_KYC.apk", isSuspicious: true },
      { id: "s18-5", text: " and grant SMS permissions.", isSuspicious: true },
    ],
    explanation:
      "Installing an `.apk` file from a direct link or WhatsApp message and granting SMS permissions allows malware to silently read and forward your banking OTPs to attackers.",
    keyTakeaway: "Never install `.apk` files received via SMS, WhatsApp, or raw IP links.",
  },

  // ==========================================================================
  // 19–24: IMPERSONATION, TECH SUPPORT & AUTHORITY SCAMS
  // ==========================================================================
  {
    id: "q19-campus-it-password-request",
    title: "Campus IT Admin Password Request",
    category: "Impersonation Scams",
    difficulty: "Beginner",
    channel: "Email",
    sender: "it-helpdesk-admin@campus-portal-support.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s19-1", text: "From: Chief IT Security Officer. ", isSuspicious: true },
      { id: "s19-2", text: "Mandatory student portal migration is underway. ", isSuspicious: false },
      { id: "s19-3", text: "Reply to this email with your current password and 6-digit SMS code", isSuspicious: true },
      { id: "s19-4", text: " ", isSuspicious: false },
      { id: "s19-5", text: "within 1 hour to prevent account deletion.", isSuspicious: true },
    ],
    explanation:
      "Legitimate IT administrators never need your password or 6-digit SMS code to perform server maintenance or account migrations.",
    keyTakeaway: "No real IT helpdesk or security officer will ever ask you to reply with your password or OTP.",
  },
  {
    id: "q20-ceo-dean-gift-card-urgent",
    title: "Dean / Executive Urgent Gift Card Lure",
    category: "Impersonation Scams",
    difficulty: "Intermediate",
    channel: "Email",
    sender: "principal.office.urgent99@free-webmail.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s20-1", text: "Hi, I am currently in a confidential board meeting and cannot take calls. ", isSuspicious: true },
      { id: "s20-2", text: "I need you to urgently purchase five ₹2,000 digital gift cards", isSuspicious: true },
      { id: "s20-3", text: " for our guest speakers and ", isSuspicious: false },
      { id: "s20-4", text: "email me the 16-digit redemption codes in the next 20 minutes.", isSuspicious: true },
      { id: "s20-5", text: " — Principal", isSuspicious: false },
    ],
    explanation:
      "Notice the free webmail address (`@free-webmail.example`), the excuse that they 'cannot take calls', and the urgent demand for irreversible gift card redemption codes.",
    keyTakeaway: "Always verify unusual financial or gift-card requests from authority figures via a known phone number.",
  },
  {
    id: "q21-electricity-officer-anydesk",
    title: "Same-Night Power Cutoff & Remote App Trap",
    category: "Impersonation Scams",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "+91-90012-XX331",
    correctClassification: "Suspicious",
    segments: [
      { id: "s21-1", text: "Dear Consumer, ", isSuspicious: false },
      { id: "s21-2", text: "your electricity power will be disconnected tonight at 9:30 PM", isSuspicious: true },
      { id: "s21-3", text: " as your previous bill was not updated. ", isSuspicious: false },
      { id: "s21-4", text: "Immediately call officer at 98XXXXXX44", isSuspicious: true },
      { id: "s21-5", text: " and install remote screen-sharing app for verification.", isSuspicious: true },
    ],
    explanation:
      "Utility providers do not send same-night disconnection notices from personal numbers or ask you to install remote screen-sharing software.",
    keyTakeaway: "Never install remote screen-sharing apps at the request of an unknown caller or SMS.",
  },
  {
    id: "q22-customs-police-parcel-threat",
    title: "Fake Customs & Cyber Police Parcel Threat",
    category: "Impersonation Scams",
    difficulty: "Advanced",
    channel: "WhatsApp",
    sender: "Customs Clearance Cell (+91-88991-XX012)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s22-1", text: "URGENT LEGAL NOTICE: A parcel in your Aadhaar name containing prohibited items was seized. ", isSuspicious: true },
      { id: "s22-2", text: "To avoid immediate arrest warrant,", isSuspicious: true },
      { id: "s22-3", text: " join video verification and ", isSuspicious: false },
      { id: "s22-4", text: "transfer ₹25,000 refundable verification bond to RBI Safe Account", isSuspicious: true },
      { id: "s22-5", text: " via ", isSuspicious: false },
      { id: "s22-6", text: "http://clearance-bond-verify.example", isSuspicious: true },
    ],
    explanation:
      "Law enforcement and customs agencies never conduct 'video arrests' on WhatsApp or ask citizens to transfer a 'refundable verification bond' to clear their name.",
    keyTakeaway: "Police, customs, and RBI do not demand money transfers to 'verify' your innocence.",
  },
  {
    id: "q23-friend-stranded-emergency-upi",
    title: "Impersonated Friend Medical / Travel Emergency",
    category: "Impersonation Scams",
    difficulty: "Advanced",
    channel: "WhatsApp",
    sender: "Unknown Number (+91-76543-XX219)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s23-1", text: "Hey! This is Rahul, ", isSuspicious: false },
      { id: "s23-2", text: "I lost my phone and wallet at the airport and my banking app is locked.", isSuspicious: true },
      { id: "s23-3", text: " Please ", isSuspicious: false },
      { id: "s23-4", text: "urgently send ₹8,000 to this agent's UPI ID right now", isSuspicious: true },
      { id: "s23-5", text: " so I can board my flight. ", isSuspicious: false },
      { id: "s23-6", text: "Can't talk on call, battery at 2%!", isSuspicious: true },
    ],
    explanation:
      "Scammers message from an unknown number claiming to be a friend in distress who conveniently 'cannot take a voice call' and needs an immediate UPI transfer to a third party.",
    keyTakeaway: "Always call your friend's original phone number or ask a personal question only they would know before sending money.",
  },
  {
    id: "q24-fake-antivirus-invoice-callback",
    title: "Fake ₹34,999 Auto-Renewal Callback Scam",
    category: "Impersonation Scams",
    difficulty: "Intermediate",
    channel: "Email",
    sender: "billing-auto-debit@pc-shield-renew.example",
    correctClassification: "Suspicious",
    segments: [
      { id: "s24-1", text: "Thank you for renewing CyberShield Total Protection! ", isSuspicious: false },
      { id: "s24-2", text: "₹34,999 will be auto-debited from your bank account in 2 hours.", isSuspicious: true },
      { id: "s24-3", text: " To cancel this charge and get an instant refund, ", isSuspicious: false },
      { id: "s24-4", text: "call our Refund Desk at +91-8000X-XX911 and allow remote desktop access.", isSuspicious: true },
    ],
    explanation:
      "Refund/callback phishing scares you with a fabricated ₹34,999 charge you never made so that you call a fake support number and grant remote access to your computer.",
    keyTakeaway: "Check your actual bank statement first; if no charge exists, ignore fake auto-debit cancellation emails.",
  },

  // ==========================================================================
  // 25–30: PAYMENT, ADVANCE-FEE, JOB/INTERNSHIP & DELIVERY SCAMS
  // ==========================================================================
  {
    id: "q25-internship-laptop-fee",
    title: "Remote Internship Laptop Security Deposit",
    category: "Job & Internship Scams",
    difficulty: "Intermediate",
    channel: "WhatsApp",
    sender: "HR Recruiting Desk (+91-81234-XX900)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s25-1", text: "Hello Candidate, ", isSuspicious: false },
      { id: "s25-2", text: "you have been selected for our Work-From-Home Software Internship (Stipend ₹30,000/month). ", isSuspicious: false },
      { id: "s25-3", text: "To issue your company MacBook, ", isSuspicious: false },
      { id: "s25-4", text: "pay a ₹1,250 refundable security fee now", isSuspicious: true },
      { id: "s25-5", text: " via ", isSuspicious: false },
      { id: "s25-6", text: "http://intern-laptop-fee.example/pay", isSuspicious: true },
      { id: "s25-7", text: " before 5 PM today.", isSuspicious: true },
    ],
    explanation:
      "This is an advance-fee internship scam. Demanding a 'refundable laptop security fee' upfront before onboarding is a classic recruitment fraud tactic.",
    keyTakeaway: "Never pay registration, training, or equipment deposits to secure a job or internship.",
  },
  {
    id: "q26-youtube-like-task-prepaid",
    title: "Part-Time Video Rating & Prepaid Task Scam",
    category: "Job & Internship Scams",
    difficulty: "Beginner",
    channel: "Chat",
    sender: "Digital Marketing HR (@task_payout_desk)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s26-1", text: "Earn ", isSuspicious: false },
      { id: "s26-2", text: "₹5,000 to ₹8,000 daily from your phone", isSuspicious: true },
      { id: "s26-3", text: " just by liking videos! ", isSuspicious: false },
      { id: "s26-4", text: "Deposit ₹3,000 into our VIP Task Wallet", isSuspicious: true },
      { id: "s26-5", text: " at ", isSuspicious: false },
      { id: "s26-6", text: "http://vip-task-earnings.example", isSuspicious: true },
      { id: "s26-7", text: " to unlock ₹4,500 instant commission!", isSuspicious: true },
    ],
    explanation:
      "Task scams pay a tiny initial amount to build trust, then require victims to deposit larger and larger sums ('VIP task recharges') that are never returned.",
    keyTakeaway: "Any part-time online task that requires you to deposit money to unlock your earnings is a scam.",
  },
  {
    id: "q27-parcel-address-fee-hold",
    title: "Incomplete Address ₹25 Redelivery Lure",
    category: "Delivery & Parcel Scams",
    difficulty: "Beginner",
    channel: "SMS",
    sender: "+91-96500-XX418",
    correctClassification: "Suspicious",
    segments: [
      { id: "s27-1", text: "IndiaPost Update: Your parcel #IN884120 could not be delivered due to an incomplete street number. ", isSuspicious: false },
      { id: "s27-2", text: "Update address and pay ₹25 redelivery charge within 12 hours", isSuspicious: true },
      { id: "s27-3", text: " at ", isSuspicious: false },
      { id: "s27-4", text: "http://indiapost-parcel-rebook.example/pay", isSuspicious: true },
      { id: "s27-5", text: " or package will be returned.", isSuspicious: false },
    ],
    explanation:
      "Attackers ask for a tiny fee (₹25) on a fake courier domain (`indiapost-parcel-rebook.example`) not for the ₹25 itself, but to capture your credit/debit card details and OTP.",
    keyTakeaway: "Track parcels only on the courier's official website—never pay 'redelivery fees' via SMS links.",
  },
  {
    id: "q28-olx-qr-code-buyer-scam",
    title: "Marketplace Buyer 'Scan QR to Receive Payment'",
    category: "Payment & Advance-Fee Scams",
    difficulty: "Intermediate",
    channel: "WhatsApp",
    sender: "Interested Buyer (+91-89001-XX223)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s28-1", text: "Hi, I want to buy your used study table at the full listed price of ₹3,500. ", isSuspicious: false },
      { id: "s28-2", text: "I am sending you a payment QR code—scan it and enter your UPI PIN", isSuspicious: true },
      { id: "s28-3", text: " so the ₹3,500 transfers into your account immediately.", isSuspicious: true },
    ],
    explanation:
      "Scanning a QR code and entering your UPI PIN always DEDUCTS money from your account. Fraudsters pose as eager buyers on classified sites to trick sellers into paying them.",
    keyTakeaway: "Never scan a QR code or enter your UPI PIN when you are the one supposed to RECEIVE money.",
  },
  {
    id: "q29-crypto-doubling-giveaway",
    title: "Guaranteed 200% Crypto Doubling Pool",
    category: "Payment & Advance-Fee Scams",
    difficulty: "Beginner",
    channel: "Chat",
    sender: "Quantum-AI-Trading-Admin",
    correctClassification: "Suspicious",
    segments: [
      { id: "s29-1", text: "Exclusive Student Wealth Pool: Our AI trading bot guarantees ", isSuspicious: false },
      { id: "s29-2", text: "100% risk-free 2x returns in 24 hours!", isSuspicious: true },
      { id: "s29-3", text: " Send ₹5,000 today via ", isSuspicious: false },
      { id: "s29-4", text: "http://quantum-double-payout.example", isSuspicious: true },
      { id: "s29-5", text: " and receive ₹10,000 tomorrow morning—guaranteed!", isSuspicious: true },
    ],
    explanation:
      "No legitimate financial instrument can guarantee doubling your money in 24 hours without risk. This is a classic advance-fee investment fraud.",
    keyTakeaway: "Promises of guaranteed high returns in hours or days are always financial scams.",
  },
  {
    id: "q30-fake-hostel-booking-deposit",
    title: "Urgent PG / Hostel Room Token Deposit",
    category: "Payment & Advance-Fee Scams",
    difficulty: "Advanced",
    channel: "WhatsApp",
    sender: "Sunrise Student PG (+91-72009-XX551)",
    correctClassification: "Suspicious",
    segments: [
      { id: "s30-1", text: "Hello, 4 other students are waiting outside to take the AC single room. ", isSuspicious: false },
      { id: "s30-2", text: "We do not allow physical visits before booking.", isSuspicious: true },
      { id: "s30-3", text: " Transfer ", isSuspicious: false },
      { id: "s30-4", text: "₹4,000 non-refundable gate-pass token within 10 minutes", isSuspicious: true },
      { id: "s30-5", text: " to reserve the room before we give it away.", isSuspicious: true },
    ],
    explanation:
      "Refusing an in-person visit while demanding an immediate 'gate-pass/visiting token fee' under artificial competition is a widespread rental deposit scam targeting students.",
    keyTakeaway: "Never pay a 'visiting pass' or booking deposit for a room you are not allowed to inspect in person first.",
  },

  // ==========================================================================
  // 31–44: LEGITIMATE PERSONAL, ACADEMIC & SERVICE MESSAGES
  // (Carefully written—including safe uses of words like 'account', 'link', 'payment')
  // ==========================================================================
  {
    id: "q31-campus-project-review",
    title: "Final-Year Project Lab Schedule",
    category: "Legitimate Academic Notice",
    difficulty: "Beginner",
    channel: "Campus Notice",
    sender: "prof.sharma@cs.university.edu",
    correctClassification: "Legitimate",
    segments: [
      { id: "s31-1", text: "Hi everyone, ", isSuspicious: false },
      { id: "s31-2", text: "tomorrow's BCA final-year project review ", isSuspicious: false },
      { id: "s31-3", text: "will be held in Lab 3 at 2:30 PM. ", isSuspicious: false },
      { id: "s31-4", text: "Please bring your architecture diagrams ", isSuspicious: false },
      { id: "s31-5", text: "and test reports for evaluation.", isSuspicious: false },
    ],
    explanation:
      "This is a normal academic scheduling message from a verified university address. It contains no deceptive links, no artificial panic, and no requests for credentials or payments.",
    keyTakeaway: "Legitimate operational messages provide clear context without pressuring you to click links or share private credentials.",
  },
  {
    id: "q32-library-book-renewal",
    title: "Library Book Due Reminder",
    category: "Legitimate Academic Notice",
    difficulty: "Beginner",
    channel: "Email",
    sender: "library-noreply@college.edu",
    correctClassification: "Legitimate",
    segments: [
      { id: "s32-1", text: "Reminder: Your borrowed copy of ", isSuspicious: false },
      { id: "s32-2", text: "'Hands-On Machine Learning' ", isSuspicious: false },
      { id: "s32-3", text: "is due back on Friday, 14 November. ", isSuspicious: false },
      { id: "s32-4", text: "You can return or renew the book in person ", isSuspicious: false },
      { id: "s32-5", text: "at the central library circulation desk.", isSuspicious: false },
    ],
    explanation:
      "This is a standard, low-risk reminder from the campus library. It names a specific item, gives a reasonable future due date, and asks you to visit the physical desk.",
    keyTakeaway: "Routine reminders that direct you to known physical desks or official portals without credential prompts are safe.",
  },
  {
    id: "q33-official-2fa-otp-warning",
    title: "Official Two-Factor Login Code",
    category: "Legitimate Security Notice",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "AD-AUTHSV",
    correctClassification: "Legitimate",
    segments: [
      { id: "s33-1", text: "Your verification code for signing in to your account is 482910. ", isSuspicious: false },
      { id: "s33-2", text: "Valid for 10 minutes. ", isSuspicious: false },
      { id: "s33-3", text: "Do not share this OTP with anyone—", isSuspicious: false },
      { id: "s33-4", text: "our staff will never ask for this code.", isSuspicious: false },
    ],
    explanation:
      "Even though this message mentions 'account' and 'OTP', it is a standard legitimate verification SMS: it contains NO external link to click and explicitly warns you never to share the code.",
    keyTakeaway: "Legitimate OTP messages warn you never to share the code; scam messages try to trick you into handing the code over.",
  },
  {
    id: "q34-tuition-payment-receipt",
    title: "Semester Tuition Payment Receipt Confirmation",
    category: "Legitimate Financial Notice",
    difficulty: "Intermediate",
    channel: "Email",
    sender: "accounts-office@university.edu",
    correctClassification: "Legitimate",
    segments: [
      { id: "s34-1", text: "Dear Student, your Semester 6 tuition fee payment of ₹24,500 ", isSuspicious: false },
      { id: "s34-2", text: "(Receipt #UNI-2026-8841) has been credited to your student account. ", isSuspicious: false },
      { id: "s34-3", text: "You may download the printed receipt anytime from the Student ERP tab. ", isSuspicious: false },
      { id: "s34-4", text: "No further action is required.", isSuspicious: false },
    ],
    explanation:
      "Although this email includes the words 'payment' and 'account', it is a purely informational receipt confirmation from the university domain that requires no link click or credential entry.",
    keyTakeaway: "The presence of words like 'payment' or 'account' does not make a message a scam when no action, fee, or login link is demanded.",
  },
  {
    id: "q35-classmate-github-repo-link",
    title: "Teammate Sharing Official Documentation Link",
    category: "Legitimate Personal Message",
    difficulty: "Intermediate",
    channel: "WhatsApp",
    sender: "Ananya (Project Teammate)",
    correctClassification: "Legitimate",
    segments: [
      { id: "s35-1", text: "Hey! I pushed the updated Random Forest unit tests. ", isSuspicious: false },
      { id: "s35-2", text: "Here is the official scikit-learn documentation link we used for the confusion matrix: ", isSuspicious: false },
      { id: "s35-3", text: "https://scikit-learn.org/stable/modules/model_evaluation.html", isSuspicious: false },
      { id: "s35-4", text: " — let's review it before tomorrow's viva.", isSuspicious: false },
    ],
    explanation:
      "While this message contains a 'link', it is a known teammate sharing an HTTPS reference on the official `scikit-learn.org` domain with clear academic context.",
    keyTakeaway: "Links to well-known HTTPS documentation domains in expected conversations without login prompts are safe.",
  },
  {
    id: "q36-bank-scheduled-maintenance",
    title: "Scheduled UPI Maintenance Advisory",
    category: "Legitimate Financial Notice",
    difficulty: "Advanced",
    channel: "SMS",
    sender: "VM-SBIBNK",
    correctClassification: "Legitimate",
    segments: [
      { id: "s36-1", text: "Dear Customer, scheduled maintenance on our UPI and NetBanking account services ", isSuspicious: false },
      { id: "s36-2", text: "will take place on Sunday from 01:00 AM to 03:30 AM IST. ", isSuspicious: false },
      { id: "s36-3", text: "Services will resume automatically afterward. ", isSuspicious: false },
      { id: "s36-4", text: "We regret the inconvenience.", isSuspicious: false },
    ],
    explanation:
      "This official bank advisory mentions 'UPI' and 'NetBanking account services', but it is purely informational, includes no external URLs, and asks for zero user action.",
    keyTakeaway: "Legitimate maintenance advisories inform you of downtime beforehand and never ask you to 're-verify' your account.",
  },
  {
    id: "q37-placement-interview-no-fee",
    title: "Campus Placement Cell Interview Schedule",
    category: "Legitimate Academic Notice",
    difficulty: "Advanced",
    channel: "Email",
    sender: "placement-cell@college.edu",
    correctClassification: "Legitimate",
    segments: [
      { id: "s37-1", text: "Dear Final-Year Students, ", isSuspicious: false },
      { id: "s37-2", text: "the on-campus coding test for TechNova Systems is scheduled on Thursday at 10:00 AM in Seminar Hall 1. ", isSuspicious: false },
      { id: "s37-3", text: "Carry your college ID card and resume. ", isSuspicious: false },
      { id: "s37-4", text: "Reminder: The placement cell never asks for any registration payment.", isSuspicious: false },
    ],
    explanation:
      "Sent from the official placement cell address, this notice gives a physical campus venue, requires standard ID documents, and explicitly reminds students that no payment is ever charged.",
    keyTakeaway: "Authentic campus placement notices take place through official college channels and never charge registration fees.",
  },
  {
    id: "q38-doctor-appointment-reminder",
    title: "Clinic Dental Checkup Reminder",
    category: "Legitimate Service Reminder",
    difficulty: "Beginner",
    channel: "SMS",
    sender: "AD-CLNDNT",
    correctClassification: "Legitimate",
    segments: [
      { id: "s38-1", text: "Appointment Reminder: Your dental checkup with Dr. Menon ", isSuspicious: false },
      { id: "s38-2", text: "is confirmed for Saturday, 8 Nov at 11:15 AM at City Care Clinic. ", isSuspicious: false },
      { id: "s38-3", text: "Please arrive 10 minutes early at the reception desk.", isSuspicious: false },
    ],
    explanation:
      "A straightforward appointment confirmation with a specific doctor, date, time, and physical clinic location—with no suspicious links or payment demands.",
    keyTakeaway: "Standard service reminders that require no sensitive data or external link clicks are safe.",
  },
  {
    id: "q39-roommate-electricity-split",
    title: "Roommate Splitting Monthly Wi-Fi Bill",
    category: "Legitimate Personal Message",
    difficulty: "Intermediate",
    channel: "WhatsApp",
    sender: "Karthik (Flatmate)",
    correctClassification: "Legitimate",
    segments: [
      { id: "s39-1", text: "Hey, I just paid this month's ₹900 fiber Wi-Fi bill from my account. ", isSuspicious: false },
      { id: "s39-2", text: "I left the printed receipt on the kitchen table. ", isSuspicious: false },
      { id: "s39-3", text: "Whenever you get time this week, you can pay me your ₹450 share.", isSuspicious: false },
    ],
    explanation:
      "Even though it mentions 'paid', 'bill', and 'account', this is a normal, unhurried message from a known flatmate referencing a physical receipt in your shared apartment.",
    keyTakeaway: "Context matters: routine bill-splitting with a known roommate without urgent links or impersonation red flags is legitimate.",
  },
  {
    id: "q40-courier-delivered-at-gate",
    title: "Order Delivered to Campus Security Gate",
    category: "Legitimate Service Reminder",
    difficulty: "Intermediate",
    channel: "SMS",
    sender: "VM-EKARTL",
    correctClassification: "Legitimate",
    segments: [
      { id: "s40-1", text: "Your prepaid order #OD409182 (Wireless Mouse) ", isSuspicious: false },
      { id: "s40-2", text: "was delivered to Main Hostel Reception Desk at 4:10 PM. ", isSuspicious: false },
      { id: "s40-3", text: "Thank you for shopping with us.", isSuspicious: false },
    ],
    explanation:
      "Unlike parcel scams that demand a redelivery fee via an unverified HTTP link, this message simply confirms that a specific item was delivered to your hostel desk.",
    keyTakeaway: "Delivery confirmations that do not ask for extra payments, OTPs, or address-update clicks are normal notifications.",
  },
  {
    id: "q41-monthly-bank-statement-ready",
    title: "Monthly e-Statement Ready in App",
    category: "Legitimate Financial Notice",
    difficulty: "Advanced",
    channel: "Email",
    sender: "statements@official-bank.example.org",
    correctClassification: "Legitimate",
    segments: [
      { id: "s41-1", text: "Dear Customer, your monthly savings account e-Statement for October ", isSuspicious: false },
      { id: "s41-2", text: "has been generated. To view it safely, ", isSuspicious: false },
      { id: "s41-3", text: "please open your official mobile banking app directly ", isSuspicious: false },
      { id: "s41-4", text: "and navigate to Statements. For your security, we do not include login links in emails.", isSuspicious: false },
    ],
    explanation:
      "This email follows best security practices: it notifies you that your account statement is ready, includes NO external links, and instructs you to open the official app yourself.",
    keyTakeaway: "Security-conscious banks instruct you to open their app directly rather than clicking email login links.",
  },
  {
    id: "q42-hackathon-certificate-ready",
    title: "Inter-College Hackathon Participation Certificate",
    category: "Legitimate Academic Notice",
    difficulty: "Beginner",
    channel: "Email",
    sender: "events@cs-department.university.edu",
    correctClassification: "Legitimate",
    segments: [
      { id: "s42-1", text: "Hello Team ScamLens, thank you for presenting your project at the Annual Tech Symposium! ", isSuspicious: false },
      { id: "s42-2", text: "Printed participation certificates are ready for collection ", isSuspicious: false },
      { id: "s42-3", text: "at the Computer Science department office between 10 AM and 4 PM.", isSuspicious: false },
    ],
    explanation:
      "References an event your team actually participated in and asks you to collect physical certificates from your department office.",
    keyTakeaway: "Messages grounded in real campus activities that require no online fee or credential submission are legitimate.",
  },
  {
    id: "q43-password-changed-self-notice",
    title: "No-Link Security Confirmation Notice",
    category: "Legitimate Security Notice",
    difficulty: "Advanced",
    channel: "Email",
    sender: "no-reply@student-portal.university.edu",
    correctClassification: "Legitimate",
    segments: [
      { id: "s43-1", text: "This is an automated confirmation that your student portal account password ", isSuspicious: false },
      { id: "s43-2", text: "was updated on 30 Oct at 18:05 IST. ", isSuspicious: false },
      { id: "s43-3", text: "If you made this change, no further action is needed. ", isSuspicious: false },
      { id: "s43-4", text: "If not, please visit the Campus IT Helpdesk in Room 102 with your student ID.", isSuspicious: false },
    ],
    explanation:
      "Rather than forcing you onto a suspicious 'cancel password change' web link, this legitimate security notice directs you to the physical Campus IT Helpdesk if you need assistance.",
    keyTakeaway: "Authentic security confirmations direct you to verified official support channels rather than unverified external login links.",
  },
  {
    id: "q44-sports-club-practice-update",
    title: "College Badminton Practice Rescheduled",
    category: "Legitimate Personal Message",
    difficulty: "Beginner",
    channel: "WhatsApp",
    sender: "Sports Secretary (Campus Group)",
    correctClassification: "Legitimate",
    segments: [
      { id: "s44-1", text: "Quick update: Today's evening badminton practice at the indoor stadium ", isSuspicious: false },
      { id: "s44-2", text: "is shifted from 5:00 PM to 5:45 PM due to floor cleaning. ", isSuspicious: false },
      { id: "s44-3", text: "See you all on Court 2!", isSuspicious: false },
    ],
    explanation:
      "A simple, everyday campus club schedule update with zero financial, credential, or link-related risk signals.",
    keyTakeaway: "Everyday coordination messages without external links, urgency traps, or data requests are safe.",
  },
];
